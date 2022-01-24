#include <iostream>

#include "express_asio.hpp"

int main() {
  eah::Express app;
  app.get("/", [](const eah::Request& req, eah::Response& res) {
    std::cout << "GET / ok" << std::endl;
    res.end("GET / ok");
  });
  boost::asio::io_context ioc;
  app.listen(ioc,
             boost::asio::ip::tcp::acceptor(
                 ioc, boost::asio::ip::tcp::endpoint(
                          boost::asio::ip::make_address("127.0.0.1"), 8080)));
  return 0;
}
