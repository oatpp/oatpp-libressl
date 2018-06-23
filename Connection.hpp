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

#ifndef oatpp_libressl_Connection_hpp
#define oatpp_libressl_Connection_hpp

#include "oatpp/core/base/memory/ObjectPool.hpp"
#include "oatpp/core/data/stream/Stream.hpp"

#include <tls.h> // link -ltls

namespace oatpp { namespace libressl {
    
class Connection : public oatpp::base::Controllable, public oatpp::data::stream::IOStream {
public:
  typedef oatpp::os::io::Library Library;
  typedef struct tls* Handle;
public:
  OBJECT_POOL(libressl_Connection_Pool, Connection, 32);
  SHARED_OBJECT_POOL(libressl_Shared_Connection_Pool, Connection, 32);
private:
  Handle m_tlsHandle;
  Library::v_handle m_handle;
public:
  Connection(Handle tlsHandle, Library::v_handle handle);
public:
  
  static std::shared_ptr<Connection> createShared(Handle tlsHandle, Library::v_handle handle){
    return libressl_Shared_Connection_Pool::allocateShared(tlsHandle, handle);
  }
  
  ~Connection();
  
  Library::v_size write(const void *buff, Library::v_size count) override;
  Library::v_size read(void *buff, Library::v_size count) override;
  
  void close();
  
  Handle getTlsHandle() {
    return m_tlsHandle;
  }
  
  Library::v_handle getHandle() {
    return m_handle;
  }
  
};
  
}}

#endif /* oatpp_libressl_Connection_hpp */
