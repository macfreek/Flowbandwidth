#!/usr/bin/env ruby
# encoding: utf-8
"""Add non-blocking readline and readlines to standard I/O class."""

class NoDataAvailable < StandardError
  include IO::WaitReadable
end

class IO
  def readline_nonblock(sep=$/, limit=nil)
    """Read the current I/O stream, and returns the string up to (and including) the line separator, 
    or up to EOF. If no line is available at the moment, does not block but raises IO::WaitReadable. 
    If limit is set, the line is truncated after limit bytes. If only one integer argument is given, 
    it is assumed to be the limit. This function may raise:
    * EOFError - in case the end of the stream is reached
    * (subclass of) IO::WaitReadable - in case no data is available on the stream at the moment
    * IOError - if the stream is closed
    * (subclass of) SystemCallError - in case of other I/O errors"""
    buf = ""
    # A single numerical argument is assumed to be the limit, not the separator
    if limit == nil and sep.class == Fixnum
      limit = sep
      sep = $/
    end
    # Repeatedly call read_nonblock (or sysread if it is not available) until either
    # - raises IO::WaitReadable (= Errno::EWOULDBLOCK or Errno::EAGAIN) (no data available)
    # - it returns an empty string or nil (?) (no data available) (should never happen)
    # - an EOFError is raised
    # - more then <limit> characters have been read
    #   NOTE: if limit is reached before $sep was found, a partial line is returned (without \n)
    #   The limit for readlines() is the limit *per line*, not the limit for the total read string.
    # - [only for readline, not for readlines] the line contains $sep.
    curlimit = 1024
    forceoutput = false
    begin
      while true
        if limit
          curlimit = buf.size - limit
        end
        # TODO: use self.sysread if read_nonblock is not available
        if self.respond_to?(:read_nonblock)
          t = self.read_nonblock(curlimit)
        else
          t = self.sysread(curlimit)
          forceoutput = true
          # unlike read_nonblock(), sysread() is unbuffered, so we return the full string, 
          # even what is behind the separator (Note: readlines_nonblock() does not fix this)
        end
        if t.nil? or t.empty?
          raise NoDataAvailable, "No data available in stream", caller
        end
        buf << t
        if limit and buf.size >= limit
          forceoutput = true
          break
        end
        if t.index(sep)
          break
        end
      end
    rescue IO::WaitReadable
      if buf.size == 0
        raise
      end
    rescue EOFError, IOError, SystemCallError
      forceoutput = true
      if buf.size == 0
        raise
      end
    end
    if (not forceoutput) and (sep.size > 0)
      # We may have read data behind the line separator.
      # Put this extraneous data back in the stream buffer
      buf, lb, remainder = buf.partition(sep)
      buf << lb
      if lb.size == 0
        # no line separator found
        self.ungetc(buf)
        raise NoDataAvailable, "No full line available in stream", caller
      end
      if remainder.size > 0
        self.ungetc(remainder)
      end
    end
    return buf
  end
  
  def readlines_nonblock(sep=$/, limit=nil)
    """Reads all available lines in the IO stream and returns them in an Array. A line is terminanted with 
    the line separator (sep) or EOF. If limit is set, lines longer then limit bytes will be truncated. 
    If no lines are available, an empty array is returned.  This function may raise:
    * EOFError - in case the end of the stream is reached
    * IOError - if the stream is closed
    * SystemCallError - in case of other I/O errors"""
    ll = []
    begin
      while true
        # Add new lines until IO::WaitReadable (or another exception) is raised
        ll << self.readline_nonblock(sep, limit)
      end
    rescue IO::WaitReadable
      return ll
    rescue EOFError, IOError, SystemCallError
      if ll.size > 0
        return ll  # The output was not empty; ignore the exception if favour of returning a result
      else
        raise
      end
    end
  end

end


if __FILE__ == $0
  # Unit tests
  require 'test/unit'

  class TestNonBlockingIO < Test::Unit::TestCase
    
    def setup
      # @ios = open('200.txt','r')
      @ios = open('|ruby -e \'x=0;while x<20;puts "Line number #{x}";$stdout.flush;x+=1;sleep 0.5;end\'')
    end
    
    def teardown
      begin
        @ios.close()
      rescue IOError
        # let it pass
      end
    end
   
    def test_simple
      assert_equal(4, SimpleNumber.new(2).add(2) )
      assert_equal(4, SimpleNumber.new(2).multiply(2) )
    end
    
    def test_typecheck
      assert_raise( RuntimeError ) { SimpleNumber.new('a') }
    end
    
    def test_failure
      assert_equal(3, SimpleNumber.new(2).add(2), "Adding doesn't work" )
    end
    
  end
end

