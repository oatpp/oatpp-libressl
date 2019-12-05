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
#include <openssl/crypto.h>

#if defined(WIN32) || defined(_WIN32)
#include <io.h>
  #include <WinSock2.h>
  #include <WS2tcpip.h>
#else
  #include <netdb.h>
  #include <arpa/inet.h>
  #include <sys/socket.h>
  #include <unistd.h>
#endif

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
#if defined(WIN32) || defined(_WIN32)
    ::closesocket(clientHandle);
#else
    ::close(clientHandle);
#endif
    OATPP_LOGD("[oatpp::libressl::client::ConnectionProvider::getConnection()]", "Could not connect");
    return nullptr;
  }
  
  Connection::TLSHandle tlsHandle = tls_client();
  
  tls_configure(tlsHandle, m_config->getTLSConfig());
  
  if(tls_connect_socket(tlsHandle, clientHandle, (const char*) m_host->getData()) < 0) {
    OATPP_LOGD("[oatpp::libressl::client::ConnectionProvider::getConnection()]", "TLS could not connect. %s", tls_error(tlsHandle));
#if defined(WIN32) || defined(_WIN32)
    ::closesocket(clientHandle);
#else
    ::close(clientHandle);
#endif
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
    oatpp::data::v_io_handle m_clientHandle;
  private:
    struct addrinfo* m_result;
    struct addrinfo* m_currentResult;
    bool m_isHandleOpened;
  public:

    ConnectCoroutine(const oatpp::String& host, v_int32 port, const std::shared_ptr<Config>& config)
      : m_host(host)
      , m_port(port)
      , m_config(config)
      , m_tlsHandle(nullptr)
      , m_result(nullptr)
      , m_isHandleOpened(false)
    {}

    ~ConnectCoroutine() {

      if(m_tlsHandle != nullptr) {
        tls_close(m_tlsHandle);
        tls_free(m_tlsHandle);
      }

      if(m_result != nullptr) {
        freeaddrinfo(m_result);
      }

    }

    Action act() override {

      auto portStr = oatpp::utils::conversion::int32ToStr(m_port);

      struct addrinfo hints;

      memset(&hints, 0, sizeof(struct addrinfo));
      hints.ai_family = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_flags = 0;
      hints.ai_protocol = 0;

      // TODO make call to get addrinfo non-blocking !!!
      auto res = getaddrinfo(m_host->c_str(), portStr->c_str(), &hints, &m_result);
      if (res != 0) {
        return error<async::Error>(
          "[oatpp::network::client::SimpleTCPConnectionProvider::getConnectionAsync()]. Error. Call to getaddrinfo() faild.");
      }

      m_currentResult = m_result;

      if (m_result == nullptr) {
        return error<async::Error>(
          "[oatpp::network::client::SimpleTCPConnectionProvider::getConnectionAsync()]. Error. Call to getaddrinfo() returned no results.");
      }

      return yieldTo(&ConnectCoroutine::iterateAddrInfoResults);

    }


    Action iterateAddrInfoResults() {

      /*
       * Close previously opened socket here.
       * Don't ever close socket in the method which returns action ioWait or ioRepeat
       */
      if(m_isHandleOpened) {
        m_isHandleOpened = false;
#if defined(WIN32) || defined(_WIN32)
        ::closesocket(m_clientHandle);
#else
        ::close(m_clientHandle);
#endif

      }

      if(m_currentResult != nullptr) {

        m_clientHandle = socket(m_currentResult->ai_family, m_currentResult->ai_socktype, m_currentResult->ai_protocol);

#if defined(WIN32) || defined(_WIN32)
        if (m_clientHandle == INVALID_SOCKET) {
          m_currentResult = m_currentResult->ai_next;
          return repeat();
        }
        u_long flags = 1;
        ioctlsocket(m_clientHandle, FIONBIO, &flags);
#else
        if (m_clientHandle < 0) {
          m_currentResult = m_currentResult->ai_next;
          return repeat();
        }
        fcntl(m_clientHandle, F_SETFL, O_NONBLOCK);
#endif

#ifdef SO_NOSIGPIPE
        int yes = 1;
        v_int32 ret = setsockopt(m_clientHandle, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(int));
        if(ret < 0) {
          OATPP_LOGD("[oatpp::network::client::SimpleTCPConnectionProvider::getConnectionAsync()]", "Warning. Failed to set %s for socket", "SO_NOSIGPIPE");
        }
#endif

        m_isHandleOpened = true;
        return yieldTo(&ConnectCoroutine::doConnect);
      }

      return error<Error>("[oatpp::network::client::SimpleTCPConnectionProvider::getConnectionAsync()]: Error. Can't connect.");

    }

    Action doConnect() {

      errno = 0;

      auto res = connect(m_clientHandle, m_currentResult->ai_addr, m_currentResult->ai_addrlen);

#if defined(WIN32) || defined(_WIN32)

      auto error = WSAGetLastError();

      if(res == 0 || error == WSAEISCONN) {
        return yieldTo(&ConnectCoroutine::secureConnection);
      }
      if(error == WSAEWOULDBLOCK || error == WSAEINPROGRESS) {
        return ioWait(m_clientHandle, oatpp::async::Action::IOEventType::IO_EVENT_WRITE);
      } else if(error == WSAEINTR) {
        return ioRepeat(m_clientHandle, oatpp::async::Action::IOEventType::IO_EVENT_WRITE);
      }

#else

      if(res == 0 || errno == EISCONN) {
        return yieldTo(&ConnectCoroutine::secureConnection);
      }
      if(errno == EALREADY || errno == EINPROGRESS) {
        return ioWait(m_clientHandle, oatpp::async::Action::IOEventType::IO_EVENT_WRITE);
      } else if(errno == EINTR) {
        return ioRepeat(m_clientHandle, oatpp::async::Action::IOEventType::IO_EVENT_WRITE);
      }

#endif

      m_currentResult = m_currentResult->ai_next;
      return yieldTo(&ConnectCoroutine::iterateAddrInfoResults);

    }

    Action secureConnection() {

      if(m_tlsHandle == nullptr) {
        m_tlsHandle = tls_client();
      }
      tls_configure(m_tlsHandle, m_config->getTLSConfig());

      auto res = tls_connect_socket(m_tlsHandle, m_clientHandle, (const char*) m_host->getData());
      if(res < 0) {
        OATPP_LOGD("[oatpp::libressl::client::ConnectionProvider::getConnectionAsync(){ConnectCoroutine::secureConnection()}]", "TLS could not connect. %s, %d", tls_error(m_tlsHandle), res);
        tls_close(m_tlsHandle);
        tls_free(m_tlsHandle);
#if defined(WIN32) || defined(_WIN32)
        ::closesocket(m_clientHandle);
#else
        ::close(m_clientHandle);
#endif
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
