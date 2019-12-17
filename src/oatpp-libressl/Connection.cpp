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

#include "Connection.hpp"

namespace oatpp { namespace libressl {

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ConnectionContext

Connection::ConnectionContext::ConnectionContext(Connection* connection, data::stream::StreamType streamType, Properties&& properties)
  : Context(std::forward<Properties>(properties))
  , m_connection(connection)
  , m_streamType(streamType)
{}

void Connection::ConnectionContext::init() {

  if(!m_connection->m_initialized) {

    m_connection->m_initialized = true;

    auto tlsObject = m_connection->m_tlsObject;

    if (tlsObject->getType() == TLSObject::Type::SERVER) {

      auto res = tls_accept_cbs(tlsObject->getTLSHandle(), &m_connection->m_tlsHandle, readCallback, writeCallback, m_connection->m_stream.get());

      if (res < 0) {
        OATPP_LOGD("[oatpp::libressl::Connection::ConnectionContext::init()]", "Error on call to 'tls_accept_cbs'. res=%d", res);
      }

    } else if (tlsObject->getType() == TLSObject::Type::CLIENT) {

      m_connection->m_tlsHandle = tlsObject->getTLSHandle();
      const char* host = nullptr;
      if(tlsObject->getServerName()) {
        host = (const char*) tlsObject->getServerName()->getData();
      }
      auto res = tls_connect_cbs(m_connection->m_tlsHandle,
                                 readCallback, writeCallback,
                                 m_connection->m_stream.get(), host);

      tlsObject->annul();

      if (res < 0) {
        OATPP_LOGD("[oatpp::libressl::Connection::ConnectionContext::init()]", "Error on call to 'tls_connect_cbs'. res=%d", res);
      }

    } else {
      throw std::runtime_error("[oatpp::libressl::Connection::ConnectionContext::init()]: Error. Unknown TLSObject type.");
    }

  }

}

async::CoroutineStarter Connection::ConnectionContext::initAsync() {

  class HandshakeCoroutine : public oatpp::async::Coroutine<HandshakeCoroutine> {
  private:
    Connection* m_connection;
  public:

    HandshakeCoroutine(Connection* connection)
      : m_connection(connection)
    {}

    Action act() override {

      if(m_connection->m_initialized) {
        return finish();
      }

      auto tlsObject = m_connection->m_tlsObject;

      if (tlsObject->getType() == TLSObject::Type::SERVER) {
        return yieldTo(&HandshakeCoroutine::initServer);
      } else if (tlsObject->getType() == TLSObject::Type::CLIENT) {
        return yieldTo(&HandshakeCoroutine::initClient);
      }

      throw std::runtime_error("[oatpp::libressl::Connection::ConnectionContext::init()]: Error. Unknown TLSObject type.");

    }

    Action initServer() {

      auto tlsObject = m_connection->m_tlsObject;
      auto res = tls_accept_cbs(tlsObject->getTLSHandle(), &m_connection->m_tlsHandle, readCallback, writeCallback, m_connection->m_stream.get());

      switch(res) {

        case TLS_WANT_POLLIN:
          /* reschedule to EventIOWorker */
          return m_connection->suggestInputStreamAction(oatpp::data::IOError::WAIT_RETRY_READ);

        case TLS_WANT_POLLOUT:
          /* reschedule to EventIOWorker */
          return m_connection->suggestOutputStreamAction(oatpp::data::IOError::WAIT_RETRY_WRITE);

        case 0:
          /* Handshake successful */
          m_connection->m_initialized = true;
          return finish();

      }

      return error<Error>("[oatpp::libressl::Connection::ConnectionContext::initAsync(){initServer()}]: Error. Handshake failed.");

    }

    Action initClient() {

      auto tlsObject = m_connection->m_tlsObject;
      m_connection->m_tlsHandle = tlsObject->getTLSHandle();
      const char* host = nullptr;
      if(tlsObject->getServerName()) {
        host = (const char*) tlsObject->getServerName()->getData();
      }
      auto res = tls_connect_cbs(m_connection->m_tlsHandle,
                                 readCallback, writeCallback,
                                 m_connection->m_stream.get(), host);

      switch(res) {

        case TLS_WANT_POLLIN:
          /* reschedule to EventIOWorker */
          return m_connection->suggestInputStreamAction(oatpp::data::IOError::WAIT_RETRY_READ);

        case TLS_WANT_POLLOUT:
          /* reschedule to EventIOWorker */
          return m_connection->suggestOutputStreamAction(oatpp::data::IOError::WAIT_RETRY_WRITE);

        case 0:
          /* Handshake successful */
          tlsObject->annul();
          m_connection->m_initialized = true;
          return finish();

      }

      tlsObject->annul();
      return error<Error>("[oatpp::libressl::Connection::ConnectionContext::initAsync(){initServer()}]: Error. Handshake failed.");

    }

  };

  if(m_connection->m_initialized) {
    return nullptr;
  }

  return HandshakeCoroutine::start(m_connection);

}

bool Connection::ConnectionContext::isInitialized() const {
  return m_connection->m_initialized;
}

data::stream::StreamType Connection::ConnectionContext::getStreamType() const {
  return m_streamType;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Connection

ssize_t Connection::writeCallback(struct tls *_ctx, const void *_buf, size_t _buflen, void *_cb_arg) {

  auto stream = static_cast<IOStream*>(_cb_arg);

  auto res = stream->write(_buf, _buflen);

  if(res == oatpp::data::IOError::RETRY_READ || res == oatpp::data::IOError::WAIT_RETRY_READ ||
     res == oatpp::data::IOError::RETRY_WRITE || res == oatpp::data::IOError::WAIT_RETRY_WRITE) {
    return TLS_WANT_POLLOUT;
  }

  return (ssize_t)res;
}

ssize_t Connection::readCallback(struct tls *_ctx, void *_buf, size_t _buflen, void *_cb_arg) {

  auto stream = static_cast<IOStream*>(_cb_arg);

  auto res = stream->read(_buf, _buflen);

  if(res == oatpp::data::IOError::RETRY_READ || res == oatpp::data::IOError::WAIT_RETRY_READ ||
     res == oatpp::data::IOError::RETRY_WRITE || res == oatpp::data::IOError::WAIT_RETRY_WRITE) {
    return TLS_WANT_POLLIN;
  }

  return (ssize_t)res;

}

Connection::Connection(const std::shared_ptr<TLSObject>& tlsObject,
                       const std::shared_ptr<oatpp::data::stream::IOStream>& stream)
  : m_tlsHandle(nullptr)
  , m_tlsObject(tlsObject)
  , m_stream(stream)
  , m_initialized(false)
{

  auto& streamInContext = stream->getInputStreamContext();
  data::stream::Context::Properties inProperties;
  for(const auto& pair : streamInContext.getProperties().getAll_Unsafe()) {
    inProperties.put(pair.first, pair.second);
  }

  inProperties.put("tls", "libressl");
  inProperties.getAll();
  m_inContext = new ConnectionContext(this, streamInContext.getStreamType(), std::move(inProperties));

  auto& streamOutContext = stream->getOutputStreamContext();
  if(streamInContext == streamOutContext) {
    m_outContext = m_inContext;
  } else {

    data::stream::Context::Properties outProperties;
    for(const auto& pair : streamOutContext.getProperties().getAll_Unsafe()) {
      outProperties.put(pair.first, pair.second);
    }

    outProperties.put("tls", "libressl");
    outProperties.getAll();
    m_outContext = new ConnectionContext(this, streamOutContext.getStreamType(), std::move(outProperties));

  }

}

Connection::~Connection(){
  if(m_inContext == m_outContext) {
    delete m_inContext;
  } else {
    delete m_inContext;
    delete m_outContext;
  }
  close();
  if(m_tlsHandle != nullptr) {
    tls_free(m_tlsHandle);
  }
}

data::v_io_size Connection::write(const void *buff, v_buff_size count){
  auto result = tls_write(m_tlsHandle, buff, count);
  if(result < 0) {
    switch (result) {
      case TLS_WANT_POLLIN:
        return oatpp::data::IOError::WAIT_RETRY_READ;

      case TLS_WANT_POLLOUT:
        return oatpp::data::IOError::WAIT_RETRY_WRITE;
    }
    auto error = tls_error(m_tlsHandle);
    if(error){
      OATPP_LOGD("[oatpp::libressl::Connection::write(...)]", "error - %s", error);
    }
  }
  return result;
}

data::v_io_size Connection::read(void *buff, v_buff_size count){
  auto result = tls_read(m_tlsHandle, buff, count);
  if(result < 0) {
    switch (result) {
      case TLS_WANT_POLLIN:
        return oatpp::data::IOError::WAIT_RETRY_READ;

      case TLS_WANT_POLLOUT:
        return oatpp::data::IOError::WAIT_RETRY_WRITE;
    }
    auto error = tls_error(m_tlsHandle);
    if(error){
      OATPP_LOGD("[oatpp::libressl::Connection::read(...)]", "error - %s", error);
    }
  }
  return result;
}

oatpp::async::Action Connection::suggestOutputStreamAction(data::v_io_size ioResult) {
  switch (ioResult) {
    case oatpp::data::IOError::RETRY_READ:
      return m_stream->suggestInputStreamAction(ioResult);
    case oatpp::data::IOError::WAIT_RETRY_READ:
      return m_stream->suggestInputStreamAction(ioResult);
    default:
      return m_stream->suggestOutputStreamAction(ioResult);
  }
}

oatpp::async::Action Connection::suggestInputStreamAction(data::v_io_size ioResult) {
  switch (ioResult) {
    case oatpp::data::IOError::RETRY_WRITE:
      return m_stream->suggestOutputStreamAction(ioResult);
    case oatpp::data::IOError::WAIT_RETRY_WRITE:
      return m_stream->suggestOutputStreamAction(ioResult);
    default:
      return m_stream->suggestInputStreamAction(ioResult);
  }
}

void Connection::setOutputStreamIOMode(oatpp::data::stream::IOMode ioMode) {
  m_stream->setOutputStreamIOMode(ioMode);
}

oatpp::data::stream::IOMode Connection::getOutputStreamIOMode() {
  return m_stream->getOutputStreamIOMode();
}

oatpp::data::stream::Context& Connection::getOutputStreamContext() {
  return *m_outContext;
}

void Connection::setInputStreamIOMode(oatpp::data::stream::IOMode ioMode) {
  m_stream->setInputStreamIOMode(ioMode);
}

oatpp::data::stream::IOMode Connection::getInputStreamIOMode() {
  return m_stream->getInputStreamIOMode();
}

oatpp::data::stream::Context& Connection::getInputStreamContext() {
  return *m_inContext;
}

void Connection::close(){
  if(m_tlsHandle != nullptr) {
    tls_close(m_tlsHandle);
  }
}
  
}}
