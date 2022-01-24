//
// Created by cerussite on 1/24/22.
//

#pragma once

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>
#include <functional>
#include <regex>
#include <string>
#include <unordered_map>

namespace eah {
namespace detail {
class RequestHeader {
 private:
  std::string method_;
  std::string path_;
  std::string http_version_;
  std::unordered_map<std::string, std::string> header_;

 private:
  RequestHeader(std::string method, std::string path, std::string http_version,
                std::unordered_map<std::string, std::string> header)
      : method_(std::move(method)),
        path_(std::move(path)),
        http_version_(std::move(http_version)),
        header_(std::move(header)) {}

 public:
  static RequestHeader Parse(const std::string& header) {
    std::vector<std::string> header_lines;
    boost::algorithm::split(header_lines, header, boost::is_any_of("\n"));
    for (auto& line : header_lines) {
      boost::algorithm::trim(line);
    }

    // GET /path/to/content HTTP/1.1
    std::string method;
    std::string path;
    std::string http_version;
    {
      const auto& version_line = header_lines.at(0);
      std::vector<std::string> version_line_parts;
      boost::algorithm::split(version_line_parts, version_line,
                              boost::is_any_of(" "));
      method = version_line_parts.at(0);
      path = version_line_parts.at(1);
      http_version = version_line_parts.at(2);
    }
    std::unordered_map<std::string, std::string> header_contents;
    std::for_each(
        std::begin(header_lines) + 1, std::end(header_lines),
        [&header_contents](const std::string& line) {
          std::vector<std::string> lp;
          boost::algorithm::split(lp, line, boost::is_any_of(":"));
          for (auto& c : lp) {
            boost::algorithm::trim(c);
          }
          if (lp.size() >= 2) {
            header_contents[boost::algorithm::to_lower_copy(lp.at(0))] =
                lp.at(1);
          }
        });
    return {std::move(method), std::move(path), std::move(http_version),
            std::move(header_contents)};
  }

 public:
  [[nodiscard]] const std::string& method() const noexcept { return method_; }
  [[nodiscard]] const std::string& path() const noexcept { return path_; }
  [[nodiscard]] const std::string& version() const noexcept {
    return http_version_;
  }
  [[nodiscard]] const std::unordered_map<std::string, std::string>& headers()
      const noexcept {
    return header_;
  }
  [[nodiscard]] const std::optional<std::string> header(std::string key) const {
    boost::algorithm::to_lower(key);
    auto itr = header_.find(key);
    if (itr == std::end(header_)) {
      return std::nullopt;
    }
    return itr->second;
  }
  [[nodiscard]] bool isBodyExists() const {
    return method_ == "POST" || method_ == "PUT";
  }
};

}  // namespace detail

class Request {
 private:
  detail::RequestHeader header_;
  std::string body_;

 public:
  Request(detail::RequestHeader header, std::string body)
      : header_(std::move(header)), body_(std::move(body)) {}

 public:
  [[nodiscard]] const detail::RequestHeader& header() const noexcept {
    return header_;
  }
  [[nodiscard]] const std::string& body() const noexcept { return body_; }
};

namespace detail {

template <class Protocol>
class BasicHttpSocket {
 public:
  using ProtocolType = Protocol;
  using SocketType = typename ProtocolType::socket;

 private:
  SocketType socket_;
  boost::asio::streambuf buffer_;

 public:
  explicit BasicHttpSocket(boost::asio::io_context& ioc) : socket_(ioc) {}

 public:
  SocketType& getSocket() { return socket_; }

 public:
  template <class Delim, class F>
  void readUntil(Delim&& delimiter, F&& callback) {
    boost::asio::async_read_until(
        socket_, buffer_, std::forward<Delim>(delimiter),
        [this, callback = std::forward<F>(callback)](
            const boost::system::error_code& error, size_t bytes_transferred) {
          if (error) {
            BOOST_LOG_TRIVIAL(error)
                << "read header error: " << error.message();
            return;
          }
          auto buf_top = boost::asio::buffer_cast<const char*>(buffer_.data());
          std::string buf(buf_top, buf_top + bytes_transferred);
          buffer_.consume(bytes_transferred);
          callback(buf);
        });
  }

 private:
  template <class F>
  void onReadExact(const boost::system::error_code& error,
                   size_t bytes_transferred, F&& callback) {
    if (error) {
      BOOST_LOG_TRIVIAL(error) << "read exact error: " << error.message();
      return;
    }
    auto buf_top = boost::asio::buffer_cast<const char*>(buffer_.data());
    std::string buf(buf_top, buf_top + bytes_transferred);
    buffer_.consume(bytes_transferred);
    callback(buf);
  }

 public:
  template <class F>
  void readExact(std::size_t size, F&& callback) {
    if (buffer_.size() >= size) {
      onReadExact(boost::system::error_code{}, size, std::forward<F>(callback));
      return;
    }
    boost::asio::async_read(
        socket_, buffer_, boost::asio::transfer_exactly(size),
        [this, size, callback = std::forward<F>(callback)](
            const boost::system::error_code& error, size_t) {
          onReadExact(error, size, callback);
        });
  }

 public:
  void write(const std::string& payload) {
    boost::asio::async_write(
        socket_, boost::asio::buffer(payload),
        [](const boost::system::error_code& error, size_t) {
          if (error) {
            BOOST_LOG_TRIVIAL(error) << "write error: " << error.message();
          }
        });
  }
};

}  // namespace detail

template <class Protocol>
class BasicResponse {
 private:
  std::shared_ptr<detail::BasicHttpSocket<Protocol>> socket_;
  int status_;
  std::unordered_map<std::string, std::string> header_;
  std::string body_;

 public:
  BasicResponse(std::shared_ptr<detail::BasicHttpSocket<Protocol>> socket)
      : socket_(std::move(socket)), status_(200), header_(), body_() {}

 public:
  BasicResponse& status(int code) noexcept {
    status_ = code;
    return *this;
  }

  BasicResponse& body(std::string b) {
    addHeader("content-length", std::to_string(b.size()));
    body_ = std::move(b);
    return *this;
  }

  BasicResponse& addHeader(std::string key, std::string value) {
    boost::algorithm::to_lower(key);
    header_[key] = std::move(value);
    return *this;
  }

 private:
  void setStatusMessage(std::ostream& os) const {
#define SC(code, message)  \
  do {                     \
    if (status_ == code) { \
      os << message;       \
      return;              \
    }                      \
  } while (0)

    SC(100, "Continue");
    SC(101, "Switching Protocols");
    SC(103, "Early Hints");

    SC(200, "OK");
    SC(201, "Created");
    SC(202, "Accepted");
    SC(203, "Non-Authoritative Information");
    SC(204, "No Content");
    SC(205, "Reset Content");
    SC(206, "Partial Content");

    SC(300, "Multiple Choice");
    SC(301, "Moved Permanently");
    SC(302, "Found");
    SC(303, "See Other");
    SC(304, "Not Modified");
    SC(305, "Use Proxy");
    SC(307, "Temporary Redirect");
    SC(308, "Permanent Redirect");

    SC(400, "Bad Request");
    SC(401, "Unauthorized");
    SC(402, "Payment Required");
    SC(403, "Forbidden");
    SC(404, "Not Found");
    SC(405, "Method Not Allowed");
    SC(406, "Not Acceptable");
    SC(407, "Proxy Authentication Required");
    SC(408, "Request Timeout");
    SC(409, "Conflict");
    SC(410, "Gone");
    SC(411, "Length Required");
    SC(412, "Precondition Failed");
    SC(413, "Payload Too Large");
    SC(414, "URI Too Long");
    SC(415, "Unsupported Media Type");
    SC(416, "Range Not Satisfiable");
    SC(417, "Expectation Failed");
    SC(421, "Misdirected Request");
    SC(425, "Too Early");
    SC(426, "Upgrade Required");
    SC(428, "Precondition Required");
    SC(429, "Too Many Requests");
    SC(431, "Request Header Fields Too Large");
    SC(451, "Unavailable For Legal Reasons");

    SC(500, "Internal Server Error");
    SC(501, "Not Implemented");
    SC(502, "Bad Gateway");
    SC(503, "Service Unavailable");
    SC(504, "Gateway Timeout");
    SC(505, "HTTP Version Not Supported");
    SC(506, "Variant Also Negotiates");
    SC(510, "Not Extended");
    SC(511, "Network Authentication Required");

    os << "Unknown";
  }

 public:
  void end() {
    std::stringstream ss;
    ss << "HTTP/1.1 " << status_ << " ";
    setStatusMessage(ss);
    ss << "\r\n";
    for (const auto& [k, v] : header_) {
      ss << k << ": " << v << "\r\n";
    }
    ss << "\r\n";
    ss << body_;
    socket_->write(ss.str());
  }
  void end(std::string b) { body(std::move(b)).end(); }
};

namespace detail {

template <class Protocol>
class BasicHttpServer {
 public:
  using ProtocolType = Protocol;
  using AcceptorType = typename ProtocolType::acceptor;
  using ResponseType = BasicResponse<ProtocolType>;

  using Handler = std::function<void(const Request&, ResponseType&)>;

 private:
  boost::asio::io_context& ioc_;
  AcceptorType acceptor_;
  std::unordered_map<std::string, std::unordered_map<std::string, Handler>>
      handlers_;

 public:
  explicit BasicHttpServer(
      boost::asio::io_context& ioc, AcceptorType acceptor,
      std::unordered_map<std::string, std::unordered_map<std::string, Handler>>
          handlers)
      : ioc_(ioc),
        acceptor_(std::move(acceptor)),
        handlers_(std::move(handlers)) {}
  BasicHttpServer(const BasicHttpServer&) = delete;
  BasicHttpServer(BasicHttpServer&&) = delete;

  BasicHttpServer& operator=(const BasicHttpServer&) = delete;
  BasicHttpServer& operator=(BasicHttpServer&&) = delete;
  ~BasicHttpServer() = default;

 public:
  void listen() {
    auto sock = std::make_shared<BasicHttpSocket<ProtocolType>>(ioc_);
    acceptor_.async_accept(
        sock->getSocket(),
        [this, sock](const boost::system::error_code& error) {
          if (error) {
            BOOST_LOG_TRIVIAL(error) << "accept error: " << error.message();
          } else {
            sock->readUntil(
                "\r\n\r\n", [this, sock](const std::string& header_str) {
                  auto header = RequestHeader::Parse(header_str);
                  if (header.isBodyExists()) {
                    auto len_str_opt = header.header("Content-Length");
                    if (!len_str_opt.has_value()) {
                      BOOST_LOG_TRIVIAL(error)
                          << "Content-Length is not found in request header";
                      return;
                    }
                    auto length = std::stoi(len_str_opt.value());
                    sock->readExact(
                        length, [this, header, sock](const std::string& body) {
                          onRequest(sock, Request(header, body));
                        });
                    return;
                  }
                  ioc_.post([this, header, sock] {
                    onRequest(sock, Request(header, ""));
                  });
                });
          }
          listen();
        });
  }

 private:
  void onRequest(std::shared_ptr<detail::BasicHttpSocket<ProtocolType>> socket,
                 const Request& request) {
    BasicResponse res(std::move(socket));

    auto mi = handlers_.find(request.header().method());
    if (mi == std::end(handlers_)) {
      res.status(404).end("not found");
      return;
    }
    auto pi = mi->second.find(request.header().path());
    if (pi == std::end(mi->second)) {
      res.status(404).end("not found");
      return;
    }
    pi->second(request, res);
  }
};

}  // namespace detail

template <class Protocol>
class BasicExpress {
 public:
  using ServerType = detail::BasicHttpServer<Protocol>;
  using Handler = typename ServerType::Handler;

 private:
  std::unordered_map<std::string, std::unordered_map<std::string, Handler>>
      handlers_;

 private:
  void setHandler(std::string method, std::string path, Handler handler) {
    handlers_[std::move(method)][std::move(path)] = std::move(handler);
  }

 public:
  void get(std::string path, Handler handler) {
    setHandler("GET", std::move(path), std::move(handler));
  }
  void post(std::string path, Handler handler) {
    setHandler("POST", std::move(path), std::move(handler));
  }
  void put(std::string path, Handler handler) {
    setHandler("PUT", std::move(path), std::move(handler));
  }
  void del(std::string path, Handler handler) {
    setHandler("DELETE", std::move(path), std::move(handler));
  }

 public:
  void listen(boost::asio::io_context& ioc,
              typename ServerType::AcceptorType acceptor) {
    ServerType server(ioc, std::move(acceptor), handlers_);
    server.listen();
    ioc.run();
  }
  void listen(typename ServerType::AcceptorType acceptor) {
    boost::asio::io_context ioc;
    listen(ioc, std::move(acceptor));
  }
};

using Express = BasicExpress<boost::asio::ip::tcp>;
using Response = BasicResponse<boost::asio::ip::tcp>;
}  // namespace eah
