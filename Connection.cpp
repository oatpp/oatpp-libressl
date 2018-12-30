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

#include "Connection.hpp"

namespace oatpp { namespace libressl {
  
Connection::Connection(TLSHandle tlsHandle, Library::v_handle handle)
  : m_tlsHandle(tlsHandle)
  , m_handle(handle)
{
}

Connection::~Connection(){
  close();
  tls_free(m_tlsHandle);
}

Connection::Library::v_size Connection::write(const void *buff, Library::v_size count){
  auto result = tls_write(m_tlsHandle, buff, count);
  if(result <= 0) {
    if (result == TLS_WANT_POLLIN || result == TLS_WANT_POLLOUT) {
      return oatpp::data::stream::Errors::ERROR_IO_WAIT_RETRY;
    }
    auto error = tls_error(m_tlsHandle);
    if(error){
      OATPP_LOGD("[oatpp::libressl::Connection::write(...)]", "error - %s", error);
    }
  }
  return result;
}

Connection::Library::v_size Connection::read(void *buff, Library::v_size count){
  auto result = tls_read(m_tlsHandle, buff, count);
  if(result <= 0) {
    if (result == TLS_WANT_POLLIN || result == TLS_WANT_POLLOUT) {
      return oatpp::data::stream::Errors::ERROR_IO_WAIT_RETRY;
    }
    auto error = tls_error(m_tlsHandle);
    if(error){
      OATPP_LOGD("[oatpp::libressl::Connection::read(...)]", "error - %s", error);
    }
  }
  return result;
}

void Connection::close(){
  tls_close(m_tlsHandle);
  Library::handle_close(m_handle);
}
  
}}
