#!/usr/bin/env ruby
# encoding: utf-8
"""Measure bandwidth of individual flows."""

require 'pty'

# Add non-blocking readline and readlines to standard I/O class.

class NoDataAvailable < StandardError
  include IO::WaitReadable
end

class CollectorError < StandardError
end

# TODO: Use log4r for output

class IO
  def readlines_nonblock(sep=$/, allowpartial=false)
    """Reads all available lines in the IO stream and returns them in an Array. A line is 
    terminanted with the line separator (sep) or EOF. If limit is set, lines longer then limit 
    bytes will be truncated. If no lines are available, an empty array is returned.  
    This function may raise:
    * EOFError - in case the end of the stream is reached
    * IOError - if the stream is closed
    * SystemCallError - in case of other I/O errors"""
    ll = []
    buf = ""
    # Repeatedly call read_nonblock (or sysread if it is not available) until either
    # - raises IO::WaitReadable (= Errno::EWOULDBLOCK or Errno::EAGAIN) (no data available)
    # - it returns an empty string or nil (?) (no data available) (should never happen)
    # - an EOFError is raised
    curlimit = 1024
    begin
      while true
        # use self.sysread if read_nonblock is not available
        if self.respond_to?(:read_nonblock)
          t = self.read_nonblock(1024)
        else
          t = self.sysread(1024)
          allowpartial = true
          # unlike read_nonblock(), sysread() is unbuffered, so we return the full string, 
          # even what is behind the separator (Note: readlines_nonblock() does not fix this)
        end
        if t.nil? or t.empty?
          raise NoDataAvailable, "No data available in stream", caller
        end
        buf << t
      end
    rescue IO::WaitReadable
      # pass
    rescue EOFError, IOError, SystemCallError
      allowpartial = true
      if buf.size == 0
        raise
      end
    end
    if sep.size == 0
      ll << buf
    else
      while (buf.size > 0)
        # We may have read data behind the line separator.
        # Put this extraneous data back in the stream buffer
        line, lb, buf = buf.partition(sep)
        if allowpartial or (lb.size > 0)
          ll << (line << lb)
        else
          # no separator found. line contains an incomplete line
          self.ungetc(line)
        end
      end
    end
    return ll
  end
end


class Array
  def sum
    return self.reduce(0, :+)
  end
  
  def percentile(p)
    # Assuming that the array is sorted, get the p%-th entry.
    if p < 0
      return self[0]
    elsif p >=1
      return self[-1]
    else
      return self[(p*self.size).floor]
    end
  end
end

module PacketCollector
  def initialize
    """Creates resources for the packet collector."""
    raise NotImplementedError, "#{self.self.name}#initialize is not implemented"
  end
  
  def getnewmeasurements()
    """Return an array of zero or more Measurement classes, containing all previously unreported 
    measurements in order. Should ideally not block."""
    raise NotImplementedError, "#{self.self.name}#getnewmeasurements is not implemented"
  end
  
  def finished?
    return false
  end
  
  def close()
    """Cleans up after use. Should not raise exceptions."""
    # pass
  end
end

class TcpDumpCollector
  include PacketCollector
  
  def self.getSrcMacAddress(interface)
    """Find the Mac address of the given local interface. Class method."""
    raise NotImplementedError, "#{self.name}#getSrcMacAddress is not implemented"
  end
  
  def self.getdefaultgateway
    gwlist = `netstat -rn  | grep UG`
    if $?.to_i == 0  # exit status is 0 (success)
      gw = gwlist.lines.first.split.last
    else
      return nil
    end
    # TODO: check syntax of gw. E.g. eth1, en12, stf4, eth1.2 vlan3, ...
    return gw
  end
  
  def self.getmacaddress(interface)
    if interface.empty?
      return nil
    end
    if interface.respond_to?(:shellescape)
      # shell escape was introduced in Ruby 1.9.3
      escapedinterface = interface.shellescape
    else
      escapedinterface = interface.gsub(/([^A-Za-z0-9_\-.,:\/@\n])/n, "\\\\\\1").gsub(/\n/, "'\n'")
    end
    maclist = `ifconfig #{escapedinterface}  | grep ether`
    # TODO: check syntax of gw. E.g. eth1, en12, stf4, eth1.2 vlan3, ...
    if $?.to_i == 0  # exit status is 0 (success)
      return maclist.lines.first.split.last
    else
      return nil
    end
  end
  
  def initialize(interface, pcapfilter="", tcpdumpcmd="tcpdump", hostmacaddress=nil)
    @hostmac = hostmacaddress
    @finished = false
    if hostmacaddress.nil?
      
    end
    collectorcmd = [tcpdumpcmd,'-tteqn']
    # -tt adds timestamp; -e adds Ethernet length; -q keeps lines short; 
    # -n supresses reverse name lookups
    if interface
      collectorcmd << '-i' << interface
    end
    if not (pcapfilter.nil? or pcapfilter.empty?)
      collectorcmd << pcapfilter
    end
    
    # Use PTY.spawn instead of Open3.popen3 to avoid input buffering by popen3
    begin
      # TODO: use log.info to display collectorcmd
      puts "[info] Host MAC address = #{hostmacaddress}"
      puts "[info] call "+collectorcmd.inspect
      @stdout, stdin, pid = PTY.spawn(*collectorcmd)
      # stdin, @stdout, @stderr, @wait_thr = Open3.popen3(*collectorcmd)
      # pid = @wait_thr[:pid]  # pid of the started process.
      stdin.close_write
    rescue Errno::ENOENT => e
      raise CollectorError, e.to_s + ". please install tcpdump", caller
    end
  end
  
  def getnewmeasurements()
    """Return an array of zero or more Measurement classes, containing all previously unreported 
    measurements in order. Should ideally not block."""
    measurements = []
    begin
      @stdout.readlines_nonblock().each do |line|
        # Process the stdout and stderr lines of tcpdump
        # TODO: logdebug # of lines
        if m = /^(?<timestamp>\d+\.\d+) +(?<srcmac>[0-9a-fA-F:]+) .+?, length (?<length>\d+): /.match(line)
          direction = (m[:srcmac] == @hostmac) ? :outbound : :inbound
          # puts "[debug] #{m[:timestamp]} #{m[:length]} #{direction} (#{line.chomp})"
          measurements << Measurement.new(m[:timestamp].to_f, m[:length].to_i, direction)
        elsif /verbose output suppressed/.match(line)
          # TODO: logdebug
          # pass
        elsif /listening on /.match(line)
          # TODO: logdebug
          # pass
        elsif m = /^tcpdump: (?<error>.+)$/.match(line)
          puts "[error] #{m[:error]}"
          if measurements.size > 0
            puts "[info] Skipping #{measurements.size} previous measurements"
          end
          raise CollectorError, m[:error].chomp, caller
        elsif line.chomp.size > 0
          # TODO: logwarn
          puts "[info] #{line.chomp}"
          # [stderr] tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
          # [stderr] listening on en1, link-type EN10MB (Ethernet), capture size 65535 bytes
          # [stderr] tcpdump: eth4: No such device exists
          # [stderr] tcpdump: en1: You don't have permission to capture on that device
          # [stderr] ((no devices found) /dev/bpf0: Permission denied)
        end
      end
    rescue EOFError
      @finished = true
      # puts "[info] EOF. Stdout closed"
    rescue SystemCallError => e
      # Some other I/O error
      @finished = true
      puts e, e.class
    end
    return measurements
  end
  
  def finished?
    return @finished
  end
  
  def close()
    begin
      @stdout.close()
    rescue StandardError # does not catch Interupts!
      # pass
    end
  end
end

class TcpDumpFileCollector < TcpDumpCollector
  def initialize(filepath, hostmacaddress)
    @hostmac = hostmacaddress
    @finished = false
    begin
      # TODO: use log.info to display collectorcmd
      puts "[info] Host MAC address = #{hostmacaddress}"
      @stdout = File.open(filepath)
    rescue Errno::ENOENT => e
      raise CollectorError, e.to_s + "", caller
    end
  end
end

class PcapCollector
  include PacketCollector
  # Not implemented
end


class Measurement
  """Measurement of a given packet"""
  attr_reader :timestamp
  attr_reader :size
  attr_reader :direction
  
  def initialize(timestamp, size, direction)
    @timestamp = timestamp
    @size      = size
    @direction = direction
  end
  
  def stats
    return "%0.6f  %4d bytes  %s" % [@timestamp, @size, @direction]
  end
end



class TimeFrame
  """Collection of measurements in a given timeframe, for a given direction 
  (:inbound or :outbound)"""
  # We only keep track of the bandwidth per TimeFrame, not per packet.
  # Since the packets are so small and the link capacity so large, dividing the individual
  # package size by the time difference between the previous and current packet does not
  # give any meaningful result.
  attr_reader :duration
  attr_reader :inboundbytecount
  attr_reader :outboundbytecount
  
  def initialize(index, duration)
    @index     = index.to_i
    @duration  = duration.to_f
    @inmeasurements   = []
    @outmeasurements  = []
    @inboundbytecount  = 0
    @outboundbytecount = 0
  end
  
  def add_measurement(measurement)
    # assert self.starttime < measurement.timestamp < self.endtime
    if measurement.direction == :inbound
      @inmeasurements << measurement
      @inboundbytecount += measurement.size
    elsif measurement.direction == :outbound
      @outmeasurements << measurement
      @outboundbytecount += measurement.size
    else
      raise RuntimeError, "Unknown direction #{measurement.direction.to_s}"
    end
  end
  
  def starttime
    return @index * @duration
  end
  
  def endtime
    return (@index + 1) * @duration
  end
  
  def size
    return self.inboundpacketcount + self.outboundpacketcount
  end
  
  def inboundpacketcount
    return @inmeasurements.size
  end
  
  def outboundpacketcount
    return @outmeasurements.size
  end
  
  def stats
    return "%.1f-%.1f %8d bytes inbound (%4d packets) %8d bytes outbound (%4d packets)" % 
        [self.starttime, self.endtime, self.inboundbytecount, self.inboundpacketcount, 
        self.outboundbytecount, self.outboundpacketcount]
  end
end


class Timeline
  """All measurements so far, contained in timeframes"""
  attr_reader :timeframes
  attr_reader :duration
  attr_reader :measurements
  attr_reader :starttime
  attr_reader :endtime
  
  def initialize(duration)
    @duration  = duration.to_f
    @timeframes = []
    @lastindex = nil
    @curtimeframe = nil
    @unreported_timeframes = []
  end
  
  def index(measurement)
    return (measurement.timestamp/@duration).floor
  end
  
  def newtimeframe(index)
    curtimeframe = TimeFrame.new(index, @duration)
    @timeframes << curtimeframe
    return curtimeframe
  end
  
  def add_measurement(measurement)
    """Add measurement to a timefrime, and print statistics of any previous timeframes."""
    index = self.index(measurement)
    if @lastindex.nil?
      @starttime = measurement.timestamp
      @lastindex = index
      @curtimeframe = self.newtimeframe(index)
    end
    if @lastindex < index
      # report @lastindex ... index (exclusive)
      @unreported_timeframes << @curtimeframe unless @curtimeframe.nil?
      (@lastindex+1...index).each do |i|
        timeframe = self.newtimeframe(i)
        @unreported_timeframes << TimeFrame.new(i, @duration)
      end
      @curtimeframe = self.newtimeframe(index)
      @lastindex = index
    end
    @curtimeframe.add_measurement(measurement)
    @endtime = measurement.timestamp
    # puts measurement.stats()
  end
  
  def close
    @unreported_timeframes << @curtimeframe unless @curtimeframe.nil?
  end
  
  def unreported_timeframes
    frames = @unreported_timeframes
    @unreported_timeframes = []
    return frames
  end
  
  def inboundpacketcount
    return @timeframes.inject(0) do |sum,tf|
      sum + tf.inboundpacketcount
    end
  end
  
  def outboundpacketcount
    return @timeframes.inject(0) do |sum,tf|
      sum + tf.outboundpacketcount
    end
  end
  
  def inboundbytecount
    return @timeframes.inject(0) do |sum,tf|
      sum + tf.inboundbytecount
    end
  end
  
  def outboundbytecount
    return @timeframes.inject(0) do |sum,tf|
      sum + tf.outboundbytecount
    end
  end
  
  def stats()
    inboundbytes = @timeframes.collect do |tf|
      tf.inboundbytecount/1000.0
    end
    inboundbytes.sort!
    inboundbytesum = inboundbytes.sum
    outboundbytes = @timeframes.collect do |tf|
      tf.outboundbytecount/1000.0
    end
    outboundbytes.sort!
    outboundbytesum = outboundbytes.sum
    unless @endtime.nil? or @starttime.nil?
      duration = @endtime - @starttime
    else
      duration = 0
    end
    # stat = "%.1f-%.1f %8d bytes inbound (%4d packets) %8d bytes outbound (%4d packets)" % 
    #     [@starttime, @endtime, inboundbytesum, self.inboundpacketcount, 
    #     outboundbytesum, self.outboundpacketcount]
    # TODO: do not count partial time frames?
    stat =   "   Total          %10.1f kBytes  inbound       %10.1f kBytes  outbound" % 
        [inboundbytesum, outboundbytesum]
    stat +=   "\n                  %10d packets inbound       %10d packets outbound" % 
        [self.inboundpacketcount, self.outboundpacketcount]
    if duration > 0
      stat += "\n   Duration       %10.1f seconds (%.1f-%.1f)  %8d timeframes" % [duration, @starttime, @endtime, @timeframes.size]
      stat += "\n   Average        %10.1f kByte/s inbound       %10.1f kByte/s outbound" % 
          [inboundbytesum/duration, outboundbytesum/duration]
      stat += "\n   Maximum        %10.1f kByte/s inbound       %10.1f kByte/s outbound" % 
          [inboundbytes.percentile(1.00)/@duration, outboundbytes.percentile(1.00)/@duration]
      stat += "\n   95%% Percentile %10.1f kByte/s inbound       %10.1f kByte/s outbound" % 
          [inboundbytes.percentile(0.95)/@duration, outboundbytes.percentile(0.95)/@duration]
      stat += "\n   80%% Percentile %10.1f kByte/s inbound       %10.1f kByte/s outbound" % 
          [inboundbytes.percentile(0.80)/@duration, outboundbytes.percentile(0.80)/@duration]
      stat += "\n   Median         %10.1f kByte/s inbound       %10.1f kByte/s outbound" % 
          [inboundbytes.percentile(0.50)/@duration, outboundbytes.percentile(0.50)/@duration]
      stat += "\n   5%% Percentile  %10.1f kByte/s inbound       %10.1f kByte/s outbound" % 
          [inboundbytes.percentile(0.05)/@duration, outboundbytes.percentile(0.05)/@duration]
      # TODO: add standard deviation
    end
    return stat
  end
end



class FlowBandwidth
  """Main controller."""
  attr_reader   :interval
  attr_reader   :collector
  attr_reader   :timeline
  attr_accessor :logger
  
  def initialize(collector, interval=1.0)
    @collector = collector
    # TODO: use log.info
    @timeframes = []
    @timeline = Timeline.new(interval.to_f)
  end
  
  def collectmeasurements()
    begin
      until @collector.finished?
        sleep 0.1
        @collector.getnewmeasurements.each do |measurement|
          @timeline.add_measurement(measurement)
          @timeline.unreported_timeframes.each do |timeframe|
            puts timeframe.stats()
          end
        end
      end
    rescue StandardError => e
      # does not catch Interrupt.
      raise
    ensure
      # executed before the exception is raised
      @collector.close()
      @timeline.close()
      @timeline.unreported_timeframes.each do |timeframe|
        puts timeframe.stats()
      end
    end
  end
  
  def stats()
    return timeline.stats
  end
  
end



if __FILE__ == $0
  """Parse command line options, and call the main program."""
  require 'optparse'
  
  interval=1.0
  interface=nil
  hostmac=nil
  pcapfilter=""
  tcpdumppath='tcpdump'
  filepath=nil
  
  # Options parser
  o = OptionParser.new do |opts|
    opts.banner = "Usage: [-t <interval>] [-i <interface>] [-m <macaddress>] [pcapfilter]"
    opts.separator ""
    opts.separator "Common options:"
    
    opts.on("-t INTERVAL", "--time INTERVAL", Float, "Time interval in seconds") do |t|
      interval = t
    end
    opts.on("-i INTERFACE", "--interface INTERFACE", "Listen on interface") do |i|
      interface = i
    end
    opts.on("-m SOURCE_MAC", "--mac SOURCE_MAC", "MAC address of the interface. "+
          "Distinguishes inbound and outbound traffic") do |m|
      hostmac = m
    end
    opts.on("--tcpdump TCPDUMPBIN", "Path to Tcpdump executable") do |p|
      tcpdumppath = p
    end
    opts.on("-f FILE", "--file FILE", "File with Tcpdump output (not a pcap file), for replay later") do |f|
      filepath = f
    end
    opts.on("-h", "--help", "Show this message") do
      puts opts
      exit
    end
    opts.separator "See man pcap-filter(7) for pcapfilter syntax."
  end
  
  begin
    o.parse!(ARGV)  # removes parameters from ARGV, only arguments remain
    pcapfilter = ARGV.join(' ')
    if filepath.nil?
      # regular request, find interface and hostmac if possible.
      if interface.nil?
        interface = TcpDumpCollector.getdefaultgateway()
        if interface.nil?
          raise OptionParser::MissingArgument, 
              "Can not determine default network interface. Specify using the -i option", caller
        end
      end
      if hostmac.nil?
        hostmac = TcpDumpCollector.getmacaddress(interface)
        if hostmac.nil?
          raise OptionParser::MissingArgument, 
              "Can not determine MAC address of the source host. Specify using the -m option", caller
        end
      end
    else
      # read from file; host mac should be specified (interface is ignored)
      if hostmac.nil?
        # do not call getmacaddress(interface), as the file may come from another machine
        raise OptionParser::MissingArgument, 
            "Can not determine MAC address of the source host. Specify using the -m option", caller
      end
    end
    if hostmac == nil
      raise OptionParser::MissingArgument, 
          "Can not determine MAC address of #{interface}. Specify using the -m option", caller
    end
  rescue OptionParser::ParseError => e
    warn e
    warn o
    exit
  end
  
  begin
    if filepath.nil?
      collector = TcpDumpCollector.new(interface, pcapfilter, tcpdumppath, hostmac)
    else
      collector = TcpDumpFileCollector.new(filepath, hostmac)
    end
    fb = FlowBandwidth.new(collector, interval)
    fb.collectmeasurements()
  rescue Interrupt => e
    warn "Abort measurement"
  rescue CollectorError => e
    warn e
  rescue StandardError => e
    warn e
    raise
  end
  puts fb.stats() unless fb.nil?
end
