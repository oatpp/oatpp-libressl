/***************************************************************************
 *
 * Project         _____    __   ____   _      _
 *                (  _  )  /__\ (_  _)_| |_  _| |_
 *                 )(_)(  /(__)\  )( (_   _)(_   _)
 *                (_____)(__)(__)(__)  |_|    |_|
 *
 *
 * Copyright 2018-present, Leonid Stryzhevskyi, <lganzzzo@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************************/

#ifndef oatpp_libressl_server_ConnectionProvider_hpp
#define oatpp_libressl_server_ConnectionProvider_hpp

#include "oatpp-libressl/Config.hpp"
#include "oatpp-libressl/Connection.hpp"

#include "oatpp/network/ConnectionProvider.hpp"

namespace oatpp { namespace libressl { namespace server {

/**
 * Libressl server connection provider.
 * Extends &id:oatpp::base::Countable;, &id:oatpp::network::ServerConnectionProvider;.
 */
class ConnectionProvider : public oatpp::base::Countable, public oatpp::network::ServerConnectionProvider {
private:
  std::shared_ptr<Config> m_config;
  v_word16 m_port;
  bool m_nonBlocking;
  bool m_closed;
  data::v_io_handle m_serverHandle;
  Connection::TLSHandle m_tlsServerHandle;
private:
  data::v_io_handle instantiateServer();
  Connection::TLSHandle instantiateTLSServer();
public:
  /**
   * Constructor.
   * @param config - &id:oatpp::libressl::Config;.
   * @param port - port to listen on.
   * @param nonBlocking - set `true` to provide non-blocking &id:oatpp::data::stream::IOStream; for connection.
   * `false` for blocking &id:oatpp::data::stream::IOStream;. Default `false`.
   */
  ConnectionProvider(const std::shared_ptr<Config>& config, v_word16 port, bool nonBlocking = false);
public:

  /**
   * Create shared ConnectionProvider.
   * @param config - &id:oatpp::libressl::Config;.
   * @param port - port to listen on.
   * @param nonBlocking - set `true` to provide non-blocking &id:oatpp::data::stream::IOStream; for connection.
   * `false` for blocking &id:oatpp::data::stream::IOStream;. Default `false`.
   * @return `std::shared_ptr` to ConnectionProvider.
   */
  static std::shared_ptr<ConnectionProvider> createShared(const std::shared_ptr<Config>& config,
                                                          v_word16 port,
                                                          bool nonBlocking = false);

  /**
   * Virtual destructor.
   */
  ~ConnectionProvider();

  /**
   * Close all handles.
   */
  void close() override;

  /**
   * Get incoming connection.
   * @return &id:oatpp::data::stream::IOStream;.
   */
  std::shared_ptr<IOStream> getConnection() override;

  /**
   * No need to implement this.<br>
   * For Asynchronous IO in oatpp it is considered to be a good practice
   * to accept connections in a seperate thread with the blocking accept()
   * and then process connections in Asynchronous manner with non-blocking read/write.
   * <br>
   * *It may be implemented later*
   */
  oatpp::async::CoroutineCallForResult<const std::shared_ptr<oatpp::data::stream::IOStream>&> getConnectionAsync() override {
    /*
     *  No need to implement this.
     *  For Asynchronous IO in oatpp it is considered to be a good practice
     *  to accept connections in a seperate thread with the blocking accept()
     *  and then process connections in Asynchronous manner with non-blocking read/write
     */
    throw std::runtime_error("oatpp::libressl::server::ConnectionProvider::getConnectionAsync not implemented.");
  }
  
};
  
}}}

#endif /* oatpp_libressl_server_ConnectionProvider_hpp */
