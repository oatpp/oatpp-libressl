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

class ConnectionProvider : public oatpp::base::Controllable, public oatpp::network::ServerConnectionProvider {
private:
  std::shared_ptr<Config> m_config;
  v_word16 m_port;
  bool m_nonBlocking;
  oatpp::os::io::Library::v_handle m_serverHandle;
  Connection::TLSHandle m_tlsServerHandle;
private:
  oatpp::os::io::Library::v_handle instantiateServer();
  Connection::TLSHandle instantiateTLSServer();
public:
  ConnectionProvider(const std::shared_ptr<Config>& config, v_word16 port, bool nonBlocking = false);
public:
  
  static std::shared_ptr<ConnectionProvider> createShared(const std::shared_ptr<Config>& config,
                                                          v_word16 port,
                                                          bool nonBlocking = false){
    return std::shared_ptr<ConnectionProvider>(new ConnectionProvider(config, port, nonBlocking));
  }
  
  ~ConnectionProvider() {
    tls_close(m_tlsServerHandle);
    tls_free(m_tlsServerHandle);
    oatpp::os::io::Library::handle_close(m_serverHandle);
  }
  
  std::shared_ptr<IOStream> getConnection() override;
  
  Action getConnectionAsync(oatpp::async::AbstractCoroutine* parentCoroutine,
                            AsyncCallback callback) override {
    /**
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
