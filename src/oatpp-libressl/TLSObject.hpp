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

#ifndef oatpp_libressl_TLSObject_hpp
#define oatpp_libressl_TLSObject_hpp

#include "oatpp/core/Types.hpp"

#include <tls.h>
#include <mutex>

namespace oatpp { namespace libressl {

class TLSObject {
public:

  enum Type : v_int32 {
    SERVER = 0,
    CLIENT = 1
  };

public:
  typedef struct tls* TLSHandle;
private:
  TLSHandle m_tlsHandle;
  Type m_type;
  oatpp::String m_serverName;
  bool m_closed;
public:

  TLSObject(TLSHandle tlsHandle, Type type, const oatpp::String& serverName);

  ~TLSObject();

  TLSHandle getTLSHandle();

  Type getType();

  oatpp::String getServerName();

  void annul();

  void close();

  bool isClosed();

  std::mutex objectMutex;


};

}}

#endif // oatpp_libressl_TLSObject_hpp
