#!ruby

require 'url/version'

module URLUtils
  def initialize(*args) # :nodoc:
    @input = nil # string
    @query_encoding = Encoding::UTF_8
    @query_object = nil # URLQuery or null
    @url = nil # ParsedURL or null
  end

  # returns base_URL
  def get_the_base
    @base
  end

  def update_steps
  end

  def set_the_input(input)
    @url = ParsedURL.parse(input, base: get_the_base, encoding_override: @query_encoding)
    if @url && @url.relative_flag
      if @query_object.nil?
        @query_object = URLQuery.new(@url.query)
      else
        @query_object.update @url.query
      end
    end
    if @url.nil? && @query_object
      @query_object.clear
    end
  end

  def pre_update_steps(value=nil)
    value = @url.to_s unless value
    update_steps(value)
  end

  def href
    @url ? @url.to_s : input
  end
  alias to_s href

  def href=(value)
    # FIXME: this may raise exception
    set_the_input(value)
    pre_update_steps(value)
  end

  def origin
    return "" unless @url

    # http://tools.ietf.org/html/rfc6454#section-4
    if @url.host.nil?
      return "null" # unique_idetifier -> null
    end

    if @url.scheme == "file"
      return "null" # TODO: implementation defined value -> null
    end

    #TODO IDNA
    if @url.port.empty?
      "#{@url.scheme}://#{@url.host.downcase}"
    else
      "#{@url.scheme}://#{@url.host.downcase}:#{@url.port}"
    end
  end

  def protocol
    @url ? @url.scheme.to_s + ":" : ":"
  end

  def protocol=(value)
    return unless @url
    ParsedURL.parse(value + ":", url: url, state_override: :scheme_start_state)
    pre_update_steps
  end

  def username
    @url ? @url.username : ""
  end

  def username=(value)
    return if @url.nil? || !@url.relative_flag
    @username = utf8_percent_encode(value, :username_encode_set)
    pre_update_steps
  end

  def password
    (@url.nil? || @url.password.nil?) ? "" : @url.password
  end

  def password=(value)
    return if @url.nil? || !@url.relative_flag
    if value.empty?
      @password = nil
      pre_update_steps
      return
    end
    @password = utf8_percent_encode(value, :password_encode_set)
    pre_update_steps
  end

  def host
    return "" if @url.nil?
    return @url.host.to_s if @url.port.empty?
    "#{@url.host}:#{@url.port}"
  end

  def host=(value)
    return if @url.nil? || !@url.relative_flag
    ParsedURL.parse(value, url: url, state_override: :host_state)
    pre_update_steps
  end

  def hostname
    return "" if @url.nil?
    @url.host.to_s
  end

  def hostname=(value)
    return if @url.nil? || !@url.relative_flag
    ParsedURL.parse(value, url: url, state_override: :hostname_state)
    pre_update_steps
  end

  def port
    return "" if @url.nil?
    @url.port
  end

  def port=(value)
    return if @url.nil? || !@url.relative_flag || @url.scheme == "file"
    ParsedURL.parse(value, url: url, state_override: :port_state)
    pre_update_steps
  end

  def pathname
    return "" if @url.nil?
    return @url.scheme_data if !@url.relative_flag
    "/#{@url.path.join"/"}"
  end

  def pathname=(value)
    return if @url.nil? || !@url.relative_flag
    @url.path.clear
    ParsedURL.parse(value, url: url, state_override: :relative_path_state)
    pre_update_steps
  end

  def search
    return "" if @url.nil? || @url.query.nil? || @url.query.empty?
    "?#{@url.query}"
  end

  def search=(value)
    return if @url.nil? || !@url.relative_flag
    if value.empty?
      @url.query = nil
      query_object.clear
      pre_update_steps
      return
    end
    @input = value.sub(/\A\?/, '')
    @url.query = ''
    ParsedURL.parse(@input, url: @url, state_override: :query_state, encoding_override: @query_encoding)
    @query_object = ParsedURL.application_x_www_form_urlencoded_parser(input)
    pre_update_steps
  end

  def query
    @query_object
  end

  def query=(value)
    object = value
    return if @query_object.nil? || object.nil?
    if object.url_ojbect
      object = URLObject.new(object)
    end
    @query_object = object

    object.update_steps
  end

  def hash
    return "" if @url.nil? || @url.fragment.nil? || @url.fragment.empty?
    "##{@url.fragment}"
  end

  def hash=(value)
    return if @url.nil? || @url.scheme == 'javascript'
    if value.empty? 
      @url.fragment = nil
      pre_update_steps
      return
    end
    @input = value.sub(/\A#/, '')
    @url.fragment = ""
    ParsedURL.parse(input, url: url, state_override: :fragment_state)
    pre_update_steps
  end
end

class URLQuery
  attr_accessor :url_object # :nodoc:

  # init : string or UQLQuery or nil
  def initialize(init=nil)
    @pairs = nil
    @url_object = nil
    # @encoding = Encoding::UTF_8
    case init
    when String
      if init.empty?
        @pairs = []
      else
        @pairs = URLUtils::ParsedURL.__send__(:application_x_www_form_urlencoded_parser, init)
      end
    when URLQuery
      @pairs = []
      # TODO: is this shallow copy?
      init.to_a.each do |name, value|
        @pairs << [name.dup, value.dup]
      end
    #when Hash
      # TODO: unspecified yet
    when NilClass
      @pairs = []
    else
      raise TypeError
    end
  end

  def update_steps
    return unless @url_object
    @url_object.query = to_s
    @url_object.pre_update_steps
  end

  def get(name)
    kv = @pairs.assoc(name)
    kv ? kv.last : nil
  end

  def getAll(name)
    @pairs.inject([]){|s, (k, v)| s << v if k == name}
  end

  def set(name, value)
    raise TypeError unless value.is_a?(String)
    if kv = @pairs.assoc(name)
      kv[1] = value
    else
      @pairs.push [name, value]
    end
    update_steps
  end

  def append(name, value)
    @pairs.push [name, value]
    update_steps
  end

  def has(name)
    @pairs.assoc(name) ? true : false
  end

  def delete(name)
    @pairs.delete_if{|k, v| k == name }
    update_steps
  end

  def size
    @pairs.size
  end

  # non standard method
  def to_a
    @pairs
  end
end

class URL
  include URLUtils

  def initialize(url, base="about:blank")
    super
    base = ParsedURL.parse(base)
    raise SyntaxError unless base
    @base = base
    set_the_input(url)
    raise SyntaxError unless @url
  end
end

# :nodoc:

module URLUtils
  class Pointer # :nodoc:
    attr_accessor :ptr

    def initialize(ary)
      # ary must be Indexable
      @ary = ary
      @ptr = 0
    end

    def inc(inc) @ptr += inc end
    def dec(dec) @ptr -= dec end
    def [](idx) @ary[@ptr+idx] end
    def []=(idx, val) @ary[@ptr+idx] = val end
    def remaining; @ary[@ptr+1, @ary.size] end
    def eof?; @ptr >= @ary.size end

    def >(other); @ptr > other; end
    def <(other); @ptr < other; end
    def ==(other)
      case other
      when Integer
        @ptr == other
      when Pointer
        @ptr == other.ptr
      else
        false
      end
    end
    def >=(other); @ptr >= other; end
    def <=(other); @ptr <= other; end

    def -(other)
      case other
      when Pointer
        @ptr - other.ptr
      else
        raise ArgumentError, "Pointer#-'s argument must be Pointer"
      end
    end
  end

  class IPv6Address # :nodoc:
    attr_accessor :pieces

    def initialize(pieces=[0, 0, 0, 0, 0, 0, 0, 0])
      @pieces = pieces
    end

    # IPv6 serializer
    def to_s
      output = ""
      compress_pointer = find_first_longest_sequences_of_0
      skip_p = false
      @pieces.each_with_index do |v, i|
        if compress_pointer == i
          output << (i == 0 ? "::" : ":")
          skip_p = true
          next
        end
        if skip_p
          next if v == 0
          skip_p = false
        end
        output << v.to_s(16)
        output << ":" if i != @pieces.size - 1
      end
      output
    end

    private
    def find_first_longest_sequences_of_0
      cur = nil
      maxidx = nil
      maxlen = 1
      chain = false
      @pieces.each_with_index do |v, i|
        if v == 0
          unless chain
            chain = true
            cur = i
          end
          len = i - cur
          if len > maxlen
            maxidx = cur
            maxlen = len
          end
        else
          chain = false
        end
      end
      return maxidx
    end
  end

  class << IPv6Address
    # IPv6 parser
    def parse(input)
      # ipv6_parser
      address = IPv6Address.new
      piece_pointer = Pointer.new(address.pieces)
      compress_pointer = nil
      pointer = Pointer.new(input)
      # c = pointer[0]
      # remaining = pointer.remaining
      if pointer[0] == ?:
        unless pointer.remaining.start_with?(?:)
          return parse_error
        end
        pointer.inc 2
        piece_pointer.inc 1
        compress_pointer = piece_pointer.dup
      end

      # Main
      until pointer.eof?
        if piece_pointer == 8
          return parse_error
        end
        if pointer[0] == ?:
          if compress_pointer != nil
            return parse_error
          end
          piece_pointer.inc 1
          pointer.inc 1
          compress_pointer = piece_pointer.dup
          next
        end
        value = 0
        length = 0
        while length < 4 && /\A\h\z/ =~ pointer[0]
          value = value * 0x10 + pointer[0].to_i(16)
          pointer.inc 1
          length += 1
        end
        case pointer[0]
        when ?.
          if length == 0
            return parse_error
          end
          pointer.dec length
          break # jump to IPv4
        when ?:
          pointer.inc 1
          if pointer.eof?
            return parse_error
          end
        when nil
        else
          return parse_error
        end
        piece_pointer[0] = value
        piece_pointer.inc 1
      end

      if pointer.eof?
        # jump to Finale
      else
        # IPv4
        if piece_pointer > 6
          return parse_error
        end
        dots_seen = 0
        until pointer.eof?
          value = 0
          while /\A\d\z/ =~ pointer[0]
            value = value * 10 + pointer[0].to_i
            pointer.inc 1
          end
          if value > 255 or
            dots_seen < 3 && pointer[0] != ?. or
            dots_seen == 3 && !pointer.eof?
            return parse_error
          end
          piece_pointer[0] = piece_pointer[0] * 0x10 + value
          if dots_seen == 0 || dots_seen == 2
            pointer.inc 1
          end
          dots_seen += 1
        end
      end

      # Finale
      if compress_pointer != nil
        swaps = piece_pointer - compress_pointer
        piece_pointer.ptr = 7
        while piece_pointer != 0 && swaps != 0
          piece_pointer[0] = compress_pointer[swaps-1]
          compress_pointer[swaps-1] = 0
          piece_pointer.dec 1
          swaps -= 1
        end
      elsif compress_pointer == nil && piece_pointer != 8
        return parse_error
      end

      return address
    end

    # all parse errors in ipv6 parsing returns failure
    def parse_error
      raise ArgumentError
    end
  end

  class ParsedURL # :nodoc:
    attr_accessor :relative_flag
    attr_accessor :scheme
    attr_accessor :scheme_data
    attr_accessor :username
    attr_accessor :port
    attr_accessor :password
    attr_accessor :host
    attr_accessor :query
    attr_accessor :fragment
    attr_accessor :path

    attr_accessor :parse_errors

    def initialize
      clear
    end

    # clear a parsed URL
    def clear
      @relative_flag = false
      @scheme = ""
      @scheme_data = ""
      @username = ""
      @port = ""
      @password = nil
      @host = nil
      @query = nil
      @fragment = nil
      @path = []

      @parse_errors = []
    end

    # URL serializer
    def to_s(exclude_fragment_flag=false)
      output = @scheme.dup << ":"
      if @relative_flag
        output << "//"
        if !@username.empty? || @password
          output << @username
          if @password
            output << ":" << @password
          end
          output << "@"
        end
        output << host.to_s
        unless @port.empty?
          output << ":" << @port
        end
        output << "/" << @path.join("/")
        if @query
          output << "?" << @query
        end
      else
        output << @scheme_data
      end
      if !exclude_fragment_flag && @fragment
        output << "#" << @fragment
      end
      output
    end
  end

  class << ParsedURL
    RELATIVE_SCHEME_TABLE = {
      "ftp" => "21",
      "file" => nil,
      "gopher" => "70",
      "http" => "80",
      "https" => "443",
      "ws" => "80",
      "wss" => "443",
    }

    # url_parser
    # a string input
    # optionally with a base URL base
    # optionally with an encoding encoding override
    # optionally with an parsed URL url
    # optionally with a state override state override (if url is given)
    def parse(input, base: nil, encoding_override: Encoding::UTF_8, url: nil, state_override: nil)
      unless url
        url = ParsedURL.new
        input.strip!
      end
      state = state_override || :scheme_start_state
      buffer = ""
      at_flag = false
      bracket_flag = false
      pointer = Pointer.new(input)

      begin
        c = pointer[0]
        remaining = pointer.remaining
        #p [state, c, url.to_s]
        case state
        when :scheme_start_state
          if /[A-Za-z]/ =~ c
            buffer << c.downcase
            state = :scheme_state
          elsif state_override.nil?
            state = :no_scheme_state
            pointer.dec 1
          else
            return parse_error(url)
          end
        when :scheme_state
          if /[A-Za-z0-9+\-.]/ =~ c
            buffer << c.downcase
          elsif c == ?:
            url.scheme = buffer
            buffer = ""
            return if state_override
            url.relative_flag = true if relative_scheme?(url.scheme)
            state =
              url.scheme == "file" ? :relative_state :
              !url.relative_flag ?  :scheme_data_state :
              state = base && url.scheme == base ? :relative_or_authority_state :
              :authority_first_slash_state 
          elsif !state_override
            buffer = ""
            state = :no_scheme_state
            pointer.ptr = -1
          elsif pointer.eof?
            return
          else
            return parse_error(url)
          end
        when :scheme_data_state
          if c == ??
            url.query = ""
            state = :query_state
          elsif c == ?#
            url.fragment = ""
            state = :fragment_state
          else
            if c && !url_codepoint?(c) or c == "%" && /\A\h\h/ =~ remaining
              return parse_error(url)
            end
            if c && /[\u0009\u000A\u000D]/ !~ c
              url.scheme_data << utf_8_percent_encode(c, :simple_encode_set)
            end
          end
        when :no_scheme_state
          if !base || !relative_scheme?(base.scheme)
            return parse_error(url)
          else
            state = :relative_state
            pointer.dec 1
          end
        when :relative_or_authority_state
          if c == ?/ && remaining.start_with?(?/)
            state = :authority_ignore_slashes_state
            pointer.inc 1
          else
            parse_error(url)
            state = :relative_state
            pointer.dec 1
          end
        when :relative_state
          url.relative_flag = true
          url.scheme = base.scheme if url.scheme != "file"
          case c
          when ?/
            state = :relative_slash_state
          when ?\\
            parse_error(url)
            state = :relative_slash_state
          when ??
            url.host = base.host
            url.port = base.port
            url.path = base.path
            url.query = ""
            state = :query_state
          when ?#
            url.host = base.host
            url.port = base.port
            url.path = base.path
            url.query = base.query
            url.fragment = ""
            state = :fragment_state
          else
            url.host = base.host
            url.port = base.port
            url.path = base.path
            url.path.pop # remove url's path's last string
            state = :relative_path_state
            pointer.dec 1
          end
        when :relative_slash_state
          case c
          when ?/, ?\\
            parse_error(url) if c == ?\\
            if url.scheme == "file"
              state = :file_host_state
            else
              state = :authority_ignore_slashes_state
            end
          else
            url.host = base.host
            url.port = base.port
            state = :relative_path_state
          end
        when :authority_first_slash_state
          if c == ?/
            state = :authority_second_slash_state
          else
            parse_error(url)
            state = :authority_ignore_slashes_state
            pointer.dec 1
          end
        when :authority_second_slash_state
          if c == ?/
            state = :authority_ignore_slashes_state
          else
            parse_error(url)
            state = :authority_ignore_slashes_state
            pointer.dec 1
          end
        when :authority_ignore_slashes_state
          if c != ?/ && c != ?\\
            state = :authority_state
            pointer.dec 1
          else
            parse_error(url)
          end
        when :authority_state
          if c == ?@
            if at_flag
              parse_error(url)
              buffer.prepend "%40"
            end
            at_flag = true
            buffer.each_char.each_with_index do |code_point, i|
              if [?\u0009, ?\u000A, ?\u000D].include?(code_point)
                parse_error(url)
                next
              end
              if !url_codepoint?(code_point) && (code_point != ?% || /\A%\h\h/ !~ buffer[i, 3])
                parse_error(url)
              end
              if code_point == ":" && url.password.nil?
                url.password = ""
                next
              end
              result = utf_8_percent_encode(code_point, :default_encode_set)
              if url.password
                url.password << result
              else
                url.username << result
              end
            end
            buffer.clear
          elsif [nil, ?/, ?\\, ??, ?#].include?(c)
            pointer.dec (buffer.size + 1)
            buffer.clear
            state = :host_state
          else
            buffer << c
          end
        when :file_host_state
          if [nil, ?/, ?\\, ??, ?#].include?(c)
            pointer.dec 1
            if /\A[A-Za-z][:|]\z/ =~ buffer
              state = :relative_path_state
            else
              host = host_parser(buffer)
              return nil unless host
              url.host = host
              buffer.clear
              state = :relative_path_start_state
            end
          elsif [?\u0009, ?\u000A, ?\u000D].include?(c)
            parse_error(url)
          else
            buffer << c
          end
        when :host_state, :hostname_state
          if c == ?: && !bracket_flag
            host = host_parser(buffer)
            return nil unless host
            url.host = host
            buffer.clear
            state = :port_state
            return if state_override == :hostname_state
          elsif [nil, ?/, ?\\, ??, ?#].include?(c)
            pointer.dec 1
            host = host_parser(buffer)
            return nil unless host
            url.host = host
            buffer.clear
            state = :relative_path_start_state
            return if state_override
          elsif [?\u0009, ?\u000A, ?\u000D].include?(c)
            parse_error(url)
          else
            bracket_flag = true if c == ?[
            bracket_flag = false if c == ?]
            buffer << c
          end
        when :port_state
          if /[0-9]/ =~ c
            buffer << c
          elsif [nil, ?/, ?\\, ??, ?#].include?(c) || state_override
            remove_reading_zeros(buffer)
            if buffer == RELATIVE_SCHEME_TABLE[url.scheme]
              buffer.clear
            end
            url.port = buffer
            return if state_override
            buffer = ""
            state = :relative_path_start_state
            pointer.dec 1
          elsif [?\u0009, ?\u000A, ?\u000D].include?(c)
            parse_error(url)
          else
            parse_error(url)
            return nil
          end
        when :relative_path_start_state
          parse_error(url) if c == ?\\
          state = :relative_path_state
          pointer.dec 1 if c != ?/ && c != ?\\
        when :relative_path_state
          if [nil, ?/, ?\\].include?(c) or !state_override && (c == "?" || c == "#")
            if buffer == ".."
              url.path.pop
              url.path << "" unless [?/, ?\\].include?(c)
            elsif buffer == "." && [nil, ?/, ?\\].include?(c)
              url.path << ""
            elsif buffer != "."
              if url.scheme == "file" && url.path.empty? && /\A[A-Za-z][:|]\z/ =~ buffer
                buffer[1] = ":"
              end
              url.path << buffer.dup
            end
            buffer.clear
            if c == ??
              url.query = ""
              state = :query_state
            elsif c == ?#
              url.fragment = ""
              state = :fragment_state
            end
          elsif c == "%" && /\A2[Ee]/ =~ remaining
            pointer.inc 2
            buffer << "."
          elsif [?\u0009, ?\u000A, ?\u000D].include?(c)
            parse_error(url)
          else
            if !url_codepoint?(c) || (c == ?% && /\A\h\h/ =~ remaining)
              parse_error(url)
            end
            buffer << utf_8_percent_encode(c, :default_encode_set)
          end
        when :query_state
          if c.nil? or !state_override && c == "#"
            if url.relative_flag
              encoding_override = Encoding::UTF_8
            end
            buffer = buffer.encode(encoding_override, invalid: :replace, undef: :replace, replace: '?')
            buffer.each_byte do |byte|
              if byte < 0x21 || 0x7E < byte || [0x22, 0x23, 0x3C, 0x3E, 0x60].include?(byte)
                url.query << "%%%0X" % byte
              else
                url.query << byte.chr(encoding_override)
              end
            end
            buffer.clear
            if c == "#"
              url.fragment = ''
              state = :fragment_state
            end
          elsif [?\u0009, ?\u000A, ?\u000D].include?(c)
            parse_error(url)
          else
            if !url_codepoint?(c) and c == ?% && /\A\h\h/ !~ remaining
              parse_error(url)
            end
            buffer << c
          end
        when :fragment_state
          case c
          when nil
          when ?\u0009, ?\u000A, ?\u000D
            parse_error(url)
          else
            if !url_codepoint?(c) || (c == ?% && /\A\h\h/ =~ remaining)
              parse_error(url)
            end
            url.fragment << utf_8_percent_encode(c, :simple_encode_set)
          end
        end
      end while !pointer.eof? && (pointer.inc 1)
      return url
    end

    def parse_error(url) # :nodoc:
      url.parse_errors << caller[0]
      nil
    end

    def host_parser(input) # :nodoc:
      if input[0] == ?[
        raise unless input[-1] == ?]
        IPv6Address.parse(input[1, input.size-2])
      else
        # TODO: IDNA hell
        input.dup
      end
    end

    def host_serializer(host) # :nodoc:
      return "" unless host
      case host
      when nil
        ""
      when IPv6Address
        "[#{host}]"
      else
        # TODO: If host is a domain ...
        host
      end
    end

    def url_codepoint?(c) # :nodoc:
      /[A-Za-z0-9!$&'()*+,\-.\/:;=?@_~\u00A0-\uD7FF\uE000-\uFDCF\uFDF0-\uFFEF\u{10000}-\u{1FFFD}\u{20000}-\u{2FFFD}\u{30000}-\u{3FFFD}\u{40000}-\u{4FFFD}\u{50000}-\u{5FFFD}\u{60000}-\u{6FFFD}\u{70000}-\u{7FFFD}\u{80000}-\u{8FFFD}\u{90000}-\u{9FFFD}\u{A0000}-\u{AFFFD}\u{B0000}-\u{BFFFD}\u{C0000}-\u{CFFFD}\u{D0000}-\u{DFFFD}\u{E1000}-\u{EFFFD}\u{F0000}-\u{FFFFD}\u{100000}-\u{10FFFD}]/ =~ c
    end

    # scheme must be lower case
    def relative_scheme?(scheme) # :nodoc:
      RELATIVE_SCHEME_TABLE.key?(scheme)
    end

    def remove_reading_zeros(buffer) # :nodoc:
      buffer.sub!(/\A0+(?!\z)/, '')
      buffer
    end

    def utf_8_percent_encode(code_point, encode_set) # :nodoc:
      set = case encode_set
            when :simple_encode_set; /[\x00-\x1F\x7F-\xFF]/no
            when :default_encode_set; /[\x00-\x1F\x7F-\xFF"#<>?]/no
            when :password_encode_set; /[\x00-\x1F\x7F-\xFF"#<>?\/@\\]/no
            when :username_encode_set; /[\x00-\x1F\x7F-\xFF"#<>?\/@\\:]/no
            else raise ArgumentError, "no such encode set '#{encode_set}'"
            end
      return code_point unless set =~ code_point.b
      application_x_www_form_urlencoded_byte_serializer(code_point, enc: Encoding::UTF_8)
    end

    TBLENCWWWCOMP_ = {} # :nodoc:
    256.times do |i|
      TBLENCWWWCOMP_[i.chr] = '%%%02X' % i
    end
    TBLENCWWWCOMP_[' '] = '+'
    TBLENCWWWCOMP_.freeze
    TBLDECWWWCOMP_ = {} # :nodoc:
    256.times do |i|
      h, l = i>>4, i&15
      TBLDECWWWCOMP_['%%%X%X' % [h, l]] = i.chr
      TBLDECWWWCOMP_['%%%x%X' % [h, l]] = i.chr
      TBLDECWWWCOMP_['%%%X%x' % [h, l]] = i.chr
      TBLDECWWWCOMP_['%%%x%x' % [h, l]] = i.chr
    end
    TBLDECWWWCOMP_['+'] = ' '
    TBLDECWWWCOMP_.freeze

    private
    def application_x_www_form_urlencoded_byte_serializer(input, enc: Encoding::UTF_8) # :nodoc:
      str = input.to_s.dup
      if str.encoding != Encoding::ASCII_8BIT
        if enc && enc != Encoding::ASCII_8BIT
          str.encode!(Encoding::UTF_8, invalid: :replace, undef: :replace)
          str.encode!(enc, fallback: ->(x){"&#{x.ord};"})
        end
        str.force_encoding(Encoding::ASCII_8BIT)
      end
      str.gsub!(/[^*\-.0-9A-Z_a-z]/, TBLENCWWWCOMP_)
      str.force_encoding(Encoding::US_ASCII)
    end

    def application_x_www_form_urlencoded_parser(str, enc: Encoding::UTF_8) # :nodoc:
      separator = '&'
      use__charset_ = false
      isindex = false
      raise ArgumentError, "the input of #{self.name}.#{__method__} must be ASCII only string" unless str.ascii_only?
      ary = []
      return ary if str.empty?
      enc = Encoding.find(enc)
      str.b.each_line(separator) do |string|
        string.chomp!(separator)
        key, sep, val = string.partition('=')
        if isindex
          if sep.empty?
            val = key
            key = ''
          end
          isindex = false
        end

        if use__charset_ and key == '_charset_' and e = get_encoding(val)
          enc = e
          use__charset_ = false
        end

        key.gsub!(/\+|%\h\h/, TBLDECWWWCOMP_)
        if val
          val.gsub!(/\+|%\h\h/, TBLDECWWWCOMP_)
        else
          val = ''
        end

        ary << [key, val]
      end
      ary.each do |k, v|
        k.force_encoding(enc)
        #k.scrub!
        v.force_encoding(enc)
        #v.scrub!
      end
      ary
    end
  end
end
