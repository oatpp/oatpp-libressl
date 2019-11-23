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

#include "oatpp/core/base/memory/ObjectPool.hpp"
#include "oatpp/core/data/stream/Stream.hpp"

#include <tls.h>

namespace oatpp { namespace libressl {

/**
 * TLS Connection implementation. Extends &id:oatpp::base::Countable; and &id:oatpp::data::stream::IOStream;.
 */
class Connection : public oatpp::base::Countable, public oatpp::data::stream::IOStream {
public:
  typedef struct tls* TLSHandle;
public:
  OBJECT_POOL(libressl_Connection_Pool, Connection, 32);
  SHARED_OBJECT_POOL(libressl_Shared_Connection_Pool, Connection, 32);
private:
  TLSHandle m_tlsHandle;
  data::v_io_handle m_handle;
private:
  void setStreamIOMode(oatpp::data::stream::IOMode ioMode);
  oatpp::data::stream::IOMode getStreamIOMode();
public:
  /**
   * Constructor.
   * @param tlsHandle - `tls*`.
   * @param handle - connection handle (file descriptor). &id:oatpp::data::v_io_handle;.
   */
  Connection(TLSHandle tlsHandle, data::v_io_handle handle);
public:

  /**
   * Create shared connection.
   * @param tlsHandle - `tls*`.
   * @param handle - connection handle (file descriptor). &id:oatpp::data::v_io_handle;.
   * @return - `std::shared_ptr` to Connection.
   */
  static std::shared_ptr<Connection> createShared(TLSHandle tlsHandle, data::v_io_handle handle){
    return libressl_Shared_Connection_Pool::allocateShared(tlsHandle, handle);
  }

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

  /**
   * Get socket handle.
   * @return - &id:oatpp::data::v_io_handle;.
   */
  data::v_io_handle getHandle() {
    return m_handle;
  }
  
};
  
}}

#endif /* oatpp_libressl_Connection_hpp */
