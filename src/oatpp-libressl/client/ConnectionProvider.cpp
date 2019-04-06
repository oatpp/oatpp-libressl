/***************************************************************************
 *
 * Project         _____    __   ____   _      _
 *                (  _  )  /__\ (_  _)_| |_  _| |_
 *                 )(_)(  /(__)\  )( (_   _)(_   _)
 *                (_____)(__)(__)(__)  |_|    |_|
 *
 *
 * Copyright 2018-present, Leonid Stryzhevskyi <lganzzzo@gmail.com>
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

#include "ConnectionProvider.hpp"

#include "oatpp-libressl/Connection.hpp"

#include "oatpp/core/utils/ConversionUtils.hpp"

#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/crypto.h>

#include <unistd.h>

namespace oatpp { namespace libressl { namespace client {
  
ConnectionProvider::ConnectionProvider(const std::shared_ptr<Config>& config,
                                       const oatpp::String& host,
                                       v_word16 port)
  : m_config(config)
  , m_host(host)
  , m_port(port)
{
  
  setProperty(PROPERTY_HOST, m_host);
  setProperty(PROPERTY_PORT, oatpp::utils::conversion::int32ToStr(port));
  
  auto calback = CRYPTO_get_locking_callback();
  if(!calback) {
    OATPP_LOGD("[oatpp::libressl::client::ConnectionProvider::ConnectionProvider()]",
               "WARNING. libressl. CRYPTO_set_locking_callback is NOT set. "
               "This can cause problems using libressl in multithreaded environment! "
               "Please call oatpp::libressl::Callbacks::setDefaultCallbacks() or "
               "consider setting custom locking_callback.");
  }
}

std::shared_ptr<ConnectionProvider> ConnectionProvider::createShared(const std::shared_ptr<Config>& config,
                                                                     const oatpp::String& host,
                                                                     v_word16 port) {
  return std::shared_ptr<ConnectionProvider>(new ConnectionProvider(config, host, port));
}
  
std::shared_ptr<oatpp::data::stream::IOStream> ConnectionProvider::getConnection(){
  
  struct hostent* host = gethostbyname((const char*) m_host->getData());
  struct sockaddr_in client;
  
  if ((host == NULL) || (host->h_addr == NULL)) {
    OATPP_LOGD("[oatpp::libressl::client::ConnectionProvider::getConnection()]", "Error retrieving DNS information.");
    return nullptr;
  }
  
  bzero(&client, sizeof(client));
  client.sin_family = AF_INET;
  client.sin_port = htons(m_port);
  memcpy(&client.sin_addr, host->h_addr, host->h_length);
  
  data::v_io_handle clientHandle = socket(AF_INET, SOCK_STREAM, 0);
  
  if (clientHandle < 0) {
    OATPP_LOGD("[oatpp::libressl::client::ConnectionProvider::getConnection()]", "Error creating socket.");
    return nullptr;
  }
  
#ifdef SO_NOSIGPIPE
  int yes = 1;
  v_int32 ret = setsockopt(clientHandle, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(int));
  if(ret < 0) {
    OATPP_LOGD("[oatpp::libressl::client::ConnectionProvider::getConnection()]", "Warning failed to set %s for socket", "SO_NOSIGPIPE");
  }
#endif
  
  if (connect(clientHandle, (struct sockaddr *)&client, sizeof(client)) != 0 ) {
    ::close(clientHandle);
    OATPP_LOGD("[oatpp::libressl::client::ConnectionProvider::getConnection()]", "Could not connect");
    return nullptr;
  }
  
  Connection::TLSHandle tlsHandle = tls_client();
  
  tls_configure(tlsHandle, m_config->getTLSConfig());
  
  if(tls_connect_socket(tlsHandle, clientHandle, (const char*) m_host->getData()) < 0) {
    OATPP_LOGD("[oatpp::libressl::client::ConnectionProvider::getConnection()]", "TLS could not connect. %s", tls_error(tlsHandle));
    ::close(clientHandle);
    tls_close(tlsHandle);
    tls_free(tlsHandle);
    return nullptr;
  }
  
  return Connection::createShared(tlsHandle, clientHandle);
  
}

oatpp::async::CoroutineStarterForResult<const std::shared_ptr<oatpp::data::stream::IOStream>&> ConnectionProvider::getConnectionAsync() {
  
  class ConnectCoroutine : public oatpp::async::CoroutineWithResult<ConnectCoroutine, const std::shared_ptr<oatpp::data::stream::IOStream>&> {
  private:
    oatpp::String m_host;
    v_int32 m_port;
    std::shared_ptr<Config> m_config;
    Connection::TLSHandle m_tlsHandle;
    data::v_io_handle m_clientHandle;
    struct sockaddr_in m_client;
  public:
    
    ConnectCoroutine(const oatpp::String& host,
                     v_int32 port,
                     const std::shared_ptr<Config>& config)
      : m_host(host)
      , m_port(port)
      , m_config(config)
      , m_tlsHandle(nullptr)
    {}
    
    ~ConnectCoroutine() {
      if(m_tlsHandle != nullptr) {
        tls_close(m_tlsHandle);
        tls_free(m_tlsHandle);
      }
    }
    
    Action act() override {
      
      struct hostent* host = gethostbyname((const char*) m_host->getData());
      
      if ((host == NULL) || (host->h_addr == NULL)) {
        return error<Error>("[oatpp::libressl::client::ConnectionProvider::getConnectionAsync(){ConnectCoroutine::act()}]: Error retrieving DNS information.");
      }
      
      bzero(&m_client, sizeof(m_client));
      m_client.sin_family = AF_INET;
      m_client.sin_port = htons(m_port);
      memcpy(&m_client.sin_addr, host->h_addr, host->h_length);
      
      m_clientHandle = socket(AF_INET, SOCK_STREAM, 0);
      
      if (m_clientHandle < 0) {
        return error<Error>("[oatpp::libressl::client::ConnectionProvider::getConnectionAsync(){ConnectCoroutine::act()}]: Error creating socket.");
      }
      
      fcntl(m_clientHandle, F_SETFL, O_NONBLOCK);
      
#ifdef SO_NOSIGPIPE
      int yes = 1;
      v_int32 ret = setsockopt(m_clientHandle, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(int));
      if(ret < 0) {
        OATPP_LOGD("[oatpp::libressl::client::ConnectionProvider::getConnectionAsync(){ConnectCoroutine::act()}]", "Warning failed to set %s for socket", "SO_NOSIGPIPE");
      }
#endif
      
      return yieldTo(&ConnectCoroutine::doConnect);
      
    }
    
    Action doConnect() {
      errno = 0;
      auto res = connect(m_clientHandle, (struct sockaddr *)&m_client, sizeof(m_client));
      if(res == 0 || errno == EISCONN) {
        //return _return(Connection::createShared(m_clientHandle));
        if(m_tlsHandle == nullptr) {
          m_tlsHandle = tls_client();
        }
        tls_configure(m_tlsHandle, m_config->getTLSConfig());
        return yieldTo(&ConnectCoroutine::secureConnection);
      }
      if(errno == EALREADY || errno == EINPROGRESS) {
        return waitRetry();
      } else if(errno == EINTR) {
        return repeat();
      }
      ::close(m_clientHandle);
      return error<Error>("[oatpp::libressl::client::ConnectionProvider::getConnectionAsync(){ConnectCoroutine::doConnect()}]: Can't connect");
    }
    
    Action secureConnection() {
      auto res = tls_connect_socket(m_tlsHandle, m_clientHandle, (const char*) m_host->getData());
      if(res < 0) {
        OATPP_LOGD("[oatpp::libressl::client::ConnectionProvider::getConnectionAsync(){ConnectCoroutine::secureConnection()}]", "TLS could not connect. %s, %d", tls_error(m_tlsHandle), res);
        tls_close(m_tlsHandle);
        tls_free(m_tlsHandle);
        ::close(m_clientHandle);
        return error<Error>("[oatpp::libressl::client::ConnectionProvider::getConnectionAsync(){ConnectCoroutine::secureConnection()}]: Can't secure connect");
      }
      auto connection = Connection::createShared(m_tlsHandle, m_clientHandle);
      m_tlsHandle = nullptr; // prevent m_tlsHandle to be freed by Coroutine
      return _return(connection);
      
    }
    
  };
  
  return ConnectCoroutine::startForResult(m_host, m_port, m_config);
  
}
  
}}}
