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

#ifndef oatpp_libressl_client_ConnectionProvider_hpp
#define oatpp_libressl_client_ConnectionProvider_hpp

#include "oatpp-libressl/Config.hpp"

#include "oatpp/network/ConnectionProvider.hpp"

namespace oatpp { namespace libressl { namespace client {

class ConnectionProvider : public base::Countable, public oatpp::network::ClientConnectionProvider {
private:
  std::shared_ptr<Config> m_config;
  oatpp::String m_host;
  v_word16 m_port;
public:
  ConnectionProvider(const std::shared_ptr<Config>& config, const oatpp::String& host, v_word16 port);
public:
  
  static std::shared_ptr<ConnectionProvider> createShared(const std::shared_ptr<Config>& config,
                                                          const oatpp::String& host,
                                                          v_word16 port) {
    return std::shared_ptr<ConnectionProvider>(new ConnectionProvider(config, host, port));
  }

  void close() override {
    // DO NOTHING
  }

  std::shared_ptr<IOStream> getConnection() override;
  Action getConnectionAsync(oatpp::async::AbstractCoroutine* parentCoroutine, AsyncCallback callback) override;
  
};
  
}}}

#endif /* oatpp_libressl_client_ConnectionProvider_hpp */
