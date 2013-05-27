require 'test/unit'
require 'url'

class TestIPv6 < Test::Unit::TestCase
  IPv6Address = URLUtils::IPv6Address

  def test_ipv6_parser
    %w[::1 1:2::7:8 2001:123:456::7 2001:aff:22ee:0:33dd:444e:555f:6677].each do |str|
      assert_equal str, IPv6Address.parse(str).to_s
    end
    %w[::: 1::2::3 ::1::2 01234::2 1:01234::1 ::127.0.0.1 ::FFFF:127.0.0.1].each do |str|
      assert_raise(ArgumentError, str){ IPv6Address.parse(str) }
    end
  end
end

class TestParsedURL < Test::Unit::TestCase
  ParsedURL = URLUtils::ParsedURL

  def test_initialize
    url = ParsedURL.new
    assert_equal "", url.scheme
    assert_equal "", url.scheme_data
    assert_equal "", url.username
    assert_equal nil, url.password
    assert_equal nil, url.host
    assert_equal "", url.port
    assert_equal [], url.path
    assert_equal nil, url.query
    assert_equal nil, url.fragment
    assert_equal false, url.relative_flag

    url = ParsedURL.parse("http://example.com")
    assert_equal "http", url.scheme
    assert_equal "", url.scheme_data
    assert_equal "", url.username
    assert_equal nil, url.password
    assert_equal "example.com", url.host
    assert_equal "", url.port
    assert_equal [""], url.path
    assert_equal nil, url.query
    assert_equal nil, url.fragment
    assert_equal true, url.relative_flag

    url = ParsedURL.parse("https://foo@example.org", url: url)
    assert_equal "https", url.scheme
    assert_equal "foo", url.username
    assert_equal "example.org", url.host

    url = ParsedURL.parse("https://foo@@example.org")
    assert_equal "https", url.scheme
    assert_equal "foo%40", url.username
    assert_equal "example.org", url.host
    assert_equal 1, url.parse_errors.size

    url = ParsedURL.parse("http://foo:bar@example.com")
    assert_equal "http", url.scheme
    assert_equal "foo", url.username
    assert_equal "bar", url.password
    assert_equal "example.com", url.host

    url = ParsedURL.parse("http://foo@example.com:80")
    assert_equal "http", url.scheme
    assert_equal "foo", url.username
    assert_equal "example.com", url.host
    assert_equal "", url.port

    url = ParsedURL.parse("http://example.com:80")
    assert_equal "http", url.scheme
    assert_equal "example.com", url.host
    assert_equal "", url.port

    url = ParsedURL.parse("https://example:0443")
    assert_equal "https", url.scheme
    assert_equal "example", url.host
    assert_equal "", url.port

    url = ParsedURL.parse("http://example.com:8080")
    assert_equal "http", url.scheme
    assert_equal "example.com", url.host
    assert_equal "8080", url.port

    url = ParsedURL.parse("gopher://foo:bar@example.com:70/")
    assert_equal "gopher", url.scheme
    assert_equal "foo", url.username
    assert_equal "bar", url.password
    assert_equal "example.com", url.host
    assert_equal "", url.port
    assert_equal [""], url.path

    url = ParsedURL.parse("ws://foo:bar@example.com:80/hoge")
    assert_equal "ws", url.scheme
    assert_equal "foo", url.username
    assert_equal "bar", url.password
    assert_equal "example.com", url.host
    assert_equal "", url.port
    assert_equal ["hoge"], url.path

    url = ParsedURL.parse("wss://foo:bar@example.com:443/hoge/")
    assert_equal "wss", url.scheme
    assert_equal "foo", url.username
    assert_equal "bar", url.password
    assert_equal "example.com", url.host
    assert_equal "", url.port
    assert_equal ["hoge", ""], url.path

    url = ParsedURL.parse("ftp://foo:bar@example.com:21/hoge/fuga")
    assert_equal "ftp", url.scheme
    assert_equal "foo", url.username
    assert_equal "bar", url.password
    assert_equal "example.com", url.host
    assert_equal "", url.port
    assert_equal %w[hoge fuga], url.path

    url = ParsedURL.parse("http://foo:bar@example.com/hoge/fuga/..")
    assert_equal "http", url.scheme
    assert_equal "foo", url.username
    assert_equal "bar", url.password
    assert_equal "example.com", url.host
    assert_equal ["hoge", ""], url.path

    url = ParsedURL.parse("http://foo:bar@example.com/..hoge/fuga/../")
    assert_equal "http", url.scheme
    assert_equal "foo", url.username
    assert_equal "bar", url.password
    assert_equal "example.com", url.host
    assert_equal ["..hoge", ""], url.path

    url = ParsedURL.parse("http://foo:bar@example.com/hoge/.fuga/.")
    assert_equal "http", url.scheme
    assert_equal "foo", url.username
    assert_equal "bar", url.password
    assert_equal "example.com", url.host
    assert_equal ["hoge", ".fuga", ""], url.path

    url = ParsedURL.parse("file://carbon/c:")
    assert_equal "file", url.scheme
    assert_equal "carbon", url.host
    assert_equal "", url.port
    assert_equal %w[c:], url.path

=begin https://www.w3.org/Bugs/Public/show_bug.cgi?id=22048
    url = ParsedURL.parse("file:///c|", base: url)
    assert_equal "file", url.scheme
    assert_equal "", url.host
    assert_equal "", url.port
    assert_equal %w[c:], url.path
=end

    url = ParsedURL.parse("file://carbon/c:/hoge/fuga", base: url)
    assert_equal "file", url.scheme
    assert_equal "carbon", url.host
    assert_equal "", url.port
    assert_equal %w[c: hoge fuga], url.path

    url = ParsedURL.parse("file:///c:", base: url)
    assert_equal "file", url.scheme
    assert_equal "", url.host
    assert_equal "", url.port
    assert_equal %w[c:], url.path

    url = ParsedURL.parse("http://foo:bar@example.com/hoge/fuga")
    assert_equal "http", url.scheme
    assert_equal "foo", url.username
    assert_equal "bar", url.password
    assert_equal "example.com", url.host
    assert_equal %w[hoge fuga], url.path

    url = ParsedURL.parse("ws://example.com?foo \x22\x3C\x3E\x60\u3042%e3%A0%BB")
    assert_equal "ws", url.scheme
    assert_equal "example.com", url.host
    assert_equal [""], url.path
    assert_equal "foo%20%22%3C%3E%60%E3%81%82%e3%A0%BB", url.query

    url = ParsedURL.parse("ws://example.com?foo \x22\x3C\x3E\x60\u3042%e3%A0%BB#\u3044")
    assert_equal "ws", url.scheme
    assert_equal "example.com", url.host
    assert_equal [""], url.path
    assert_equal "foo%20%22%3C%3E%60%E3%81%82%e3%A0%BB", url.query
    assert_equal "%E3%81%84", url.fragment

    url = ParsedURL.parse("ws://example.com?foo \x22\x3C\x3E\x60\u3042%e3%A0%BB#\u3044")
    assert_equal "ws", url.scheme
    assert_equal "example.com", url.host
    assert_equal [""], url.path
    assert_equal "foo%20%22%3C%3E%60%E3%81%82%e3%A0%BB", url.query
    assert_equal "%E3%81%84", url.fragment

    url = ParsedURL.parse("ws://example.com#\u3044")
    assert_equal "ws", url.scheme
    assert_equal "example.com", url.host
    assert_equal [""], url.path
    assert_equal nil, url.query
    assert_equal "%E3%81%84", url.fragment

    url = ParsedURL.parse("ISBN:978-951-23-8888-2")
    assert_equal "isbn", url.scheme
    assert_equal "978-951-23-8888-2", url.scheme_data
    assert_equal nil, url.host
    assert_equal false, url.relative_flag

    url = ParsedURL.parse("ISBN:978-951-23-8888-2?foo")
    assert_equal "isbn", url.scheme
    assert_equal "978-951-23-8888-2", url.scheme_data
    assert_equal "foo", url.query

    url = ParsedURL.parse("ISBN:978-951-23-8888-2#hoge")
    assert_equal "isbn", url.scheme
    assert_equal "978-951-23-8888-2", url.scheme_data
    assert_equal "hoge", url.fragment

    url = ParsedURL.parse("about:blank")
    assert_equal "about", url.scheme
    assert_equal "blank", url.scheme_data
  end

  def test_remove_reading_zeros
    [ #input    output
      "42",     "42",
      "031",    "31",
      "080",    "80",
      "0000",   "0",
    ].each_slice(2) do |input, output|
      assert_equal(output, ParsedURL.__send__(:remove_reading_zeros, input))
    end
  end
end

class TestURL < Test::Unit::TestCase
  def test_initialize
    url = URL.new("  http://foo:bar@example.com:8080/hoge?1=2&3=4#fuga ")
    assert_equal "http://foo:bar@example.com:8080/hoge?1=2&3=4#fuga", url.href
    #assert_equal "http://example.com/", url.origin
    assert_equal "http:", url.protocol
    assert_equal "foo", url.username
    assert_equal "bar", url.password
    assert_equal "example.com:8080", url.host
    assert_equal "example.com", url.hostname
    assert_equal "8080", url.port
    assert_equal "/hoge", url.pathname
    assert_equal "?1=2&3=4", url.search
    q = url.query
    assert q.is_a?(URLQuery)
    assert_equal [["1", "2"], ["3", "4"]], q.to_a
    assert_equal "#fuga", url.hash

    url = URL.new("bar", "http://example.com:80/foo")
    assert_equal "http:", url.protocol
    assert_equal "example.com", url.host
    assert_equal "example.com", url.hostname
    assert_equal "", url.port
    assert_equal "/bar", url.pathname

    url = URL.new("bar", "http://example.com:80/foo/")
    assert_equal "http:", url.protocol
    assert_equal "example.com", url.host
    assert_equal "example.com", url.hostname
    assert_equal "", url.port
    assert_equal "/foo/bar", url.pathname

    url = URL.new("../bar", "https://example.com:443/foo/")
    assert_equal "https:", url.protocol
    assert_equal "example.com", url.host
    assert_equal "example.com", url.hostname
    assert_equal "", url.port
    assert_equal "/bar", url.pathname

    url = URL.new("../bar", "https://Example.com:443/foo/hoge/")
    assert_equal "https:", url.protocol
    assert_equal "Example.com", url.host
    assert_equal "Example.com", url.hostname
    assert_equal "", url.port
    assert_equal "/foo/bar", url.pathname

    # Network Path Reference
    url = URL.new("//example.org/bar", "https://Example.com:443/foo/hoge/")
    assert_equal "https:", url.protocol
    assert_equal "example.org", url.host
    assert_equal "example.org", url.hostname
    assert_equal "", url.port
    assert_equal "/bar", url.pathname

    url = URL.new("http://あ:い@日本語.jp:80/foo")
    assert_equal "http:", url.protocol
    assert_equal "%E3%81%82", url.username
    assert_equal "%E3%81%84", url.password
    assert_equal "日本語.jp", url.host
    assert_equal "日本語.jp", url.hostname
    assert_equal "", url.port
    assert_equal "/foo", url.pathname

    url = URL.new("http://%E3%81%82:%E3%81%84@example.com:80/foo")
    assert_equal "http:", url.protocol
    assert_equal "%E3%81%82", url.username
    assert_equal "%E3%81%84", url.password
    assert_equal "example.com", url.host
    assert_equal "example.com", url.hostname
    assert_equal "", url.port
    assert_equal "/foo", url.pathname
  end

  def test_query
    url = URL.new("http://example.com")
    q = url.query
    assert_equal([], q.to_a)
    q.set("foo", "bar")
    assert_equal([["foo", "bar"]], q.to_a)
    assert_equal(nil, q.url_object)

    url = URL.new("http://example.com?foo")
    assert_equal([["foo", ""]], url.query.to_a)

    url = URL.new("http://example.com?foo=bar")
    assert_equal([["foo", "bar"]], url.query.to_a)

    url = URL.new("http://example.com?foo=bar&hoge=fuga")
    assert_equal([["foo", "bar"], ["hoge", "fuga"]], url.query.to_a)

    url = URL.new("http://example.com?foo=&=fuga")
    assert_equal([["foo", ""], ["", "fuga"]], url.query.to_a)
  end
end

class TestURLQuery < Test::Unit::TestCase
  def test_initialize
    assert_equal [], URLQuery.new.to_a
    assert_equal [], URLQuery.new(nil).to_a
    assert_equal [], URLQuery.new("").to_a
    assert_raise(TypeError){ URLQuery.new(1) }

    q = URLQuery.new("a=b&c=d")
    assert_equal [%w[a b], %w[c d]], q.to_a
    assert_equal [%w[a b], %w[c d]], URLQuery.new(q).to_a
    # TODO: shallow/deep copy test
    assert_equal [%w[a b], %w[c d]], URLQuery.new("a=b&c=d").to_a
    assert_equal [["a", ""], ["", "d"]], URLQuery.new("a&=d").to_a
    assert_equal [["a", "%z"]], URLQuery.new("a=%25z").to_a
    assert_equal [["a", "%z"]], URLQuery.new("a=%z").to_a
    #assert_equal [["a", "\uFFFDz"]], URLQuery.new("a=%E3%81z").to_a
  end

  def test_get
    q = URLQuery.new
    assert_equal nil, q.get("foo")
    q.set("foo", "bar")
    assert_equal "bar", q.get("foo")
  end

  def test_getAll
    q = URLQuery.new
    q.set("foo", "bar")
    q.append("foo", "baz")
    assert_equal ["bar", "baz"], q.getAll("foo")
  end

  def test_set
    q = URLQuery.new
    assert_equal nil, q.get("foo")
    q.set("foo", "bar")
    assert_equal "bar", q.get("foo")
    q.set("foo", "baz")
    assert_equal "baz", q.get("foo")
  end

  def test_append
    q = URLQuery.new
    q.set("foo", "bar")
    q.append("foo", "baz")
    assert_equal "bar", q.get("foo")
    assert_equal ["bar", "baz"], q.getAll("foo")
  end

  def test_has
    q = URLQuery.new
    assert_equal false, q.has("foo")
    q.set("foo", "bar")
    assert_equal true, q.has("foo")
  end

  def test_delete
    q = URLQuery.new
    assert_equal false, q.has("foo")
    q.set("foo", "bar")
    assert_equal true, q.has("foo")
    q.delete("foo")
    assert_equal false, q.has("foo")
  end

  def test_size
    q = URLQuery.new
    assert_equal 0, q.size
    q.set("foo", "bar")
    assert_equal 1, q.size
    q.append("foo", "baz")
    assert_equal 2, q.size
    q.delete("foo")
    assert_equal 0, q.size
  end
end
