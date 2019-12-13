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

#ifndef oatpp_libressl_Connection_hpp
#define oatpp_libressl_Connection_hpp

#include "TLSObject.hpp"

#include "oatpp/core/base/memory/ObjectPool.hpp"
#include "oatpp/core/data/stream/Stream.hpp"

namespace oatpp { namespace libressl {

/**
 * TLS Connection implementation. Extends &id:oatpp::base::Countable; and &id:oatpp::data::stream::IOStream;.
 */
class Connection : public oatpp::base::Countable, public oatpp::data::stream::IOStream {
public:

  class ConnectionContext : public oatpp::data::stream::Context {
  private:
    Connection* m_connection;
    data::stream::StreamType m_streamType;
  public:

    ConnectionContext(Connection* connection, data::stream::StreamType streamType, Properties&& properties);

    void init() override;

    async::CoroutineStarter initAsync() override;

    bool isInitialized() const override;

    data::stream::StreamType getStreamType() const override;

  };

public:
  typedef struct tls* TLSHandle;
private:
  TLSHandle m_tlsHandle;
  std::shared_ptr<TLSObject> m_tlsObject;
  std::shared_ptr<oatpp::data::stream::IOStream> m_stream;
  std::atomic<bool> m_initialized;
private:
  ConnectionContext* m_inContext;
  ConnectionContext* m_outContext;
private:
  static ssize_t writeCallback(struct tls *_ctx, const void *_buf, size_t _buflen, void *_cb_arg);
  static ssize_t readCallback(struct tls *_ctx, void *_buf, size_t _buflen, void *_cb_arg);
public:

  /**
   * Constructor.
   * @param tlsObject - &id:oatpp::libressl::TLSObject;.
   * @param stream - underlying transport stream. &id:oatpp::data::stream::IOStream;.
   */
  Connection(const std::shared_ptr<TLSObject>& tlsObject,
             const std::shared_ptr<oatpp::data::stream::IOStream>& stream);

  /**
   * Virtual destructor.
   */
  ~Connection();

  /**
   * Implementation of &id:oatpp::data::stream::OutputStream::write; method.
   * @param buff - data to write to stream.
   * @param count - data size.
   * @return - actual amount of bytes written.
   */
  data::v_io_size write(const void *buff, v_buff_size count) override;

  /**
   * Implementation of &id:oatpp::data::stream::InputStream::read; method.
   * @param buff - buffer to read data to.
   * @param count - buffer size.
   * @return - actual amount of bytes read.
   */
  data::v_io_size read(void *buff, v_buff_size count) override;

  /**
   * Implementation of OutputStream must suggest async actions for I/O results.
   * Suggested Action is used for scheduling coroutines in async::Executor.
   * @param ioResult - result of the call to &l:OutputStream::write ();.
   * @return - &id:oatpp::async::Action;.
   */
  oatpp::async::Action suggestOutputStreamAction(data::v_io_size ioResult) override;

  /**
   * Implementation of InputStream must suggest async actions for I/O results.
   * Suggested Action is used for scheduling coroutines in async::Executor.
   * @param ioResult - result of the call to &l:InputStream::read ();.
   * @return - &id:oatpp::async::Action;.
   */
  oatpp::async::Action suggestInputStreamAction(data::v_io_size ioResult) override;

  /**
   * Set OutputStream I/O mode.
   * @param ioMode
   */
  void setOutputStreamIOMode(oatpp::data::stream::IOMode ioMode) override;

  /**
   * Set OutputStream I/O mode.
   * @return
   */
  oatpp::data::stream::IOMode getOutputStreamIOMode() override;

  /**
   * Get output stream context.
   * @return - &id:oatpp::data::stream::Context;.
   */
  oatpp::data::stream::Context& getOutputStreamContext() override;

  /**
   * Set InputStream I/O mode.
   * @param ioMode
   */
  void setInputStreamIOMode(oatpp::data::stream::IOMode ioMode) override;

  /**
   * Get InputStream I/O mode.
   * @return
   */
  oatpp::data::stream::IOMode getInputStreamIOMode() override;

  /**
   * Get input stream context. <br>
   * @return - &id:oatpp::data::stream::Context;.
   */
  oatpp::data::stream::Context& getInputStreamContext() override;


  /**
   * Close all handles.
   */
  void close();

  /**
   * Get TLS handle.
   * @return - `tls*`.
   */
  TLSHandle getTlsHandle() {
    return m_tlsHandle;
  }
  
};
  
}}

#endif /* oatpp_libressl_Connection_hpp */
