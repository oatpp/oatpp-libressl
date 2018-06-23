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

#ifndef oatpp_libressl_Config_hpp
#define oatpp_libressl_Config_hpp

#include <tls.h>
#include <memory>

namespace oatpp { namespace libressl {
  
class Config {
public:
  typedef struct tls_config* TLSConfig;
private:
  TLSConfig m_config;
public:
  Config()
    : m_config(tls_config_new())
  {}
public:
  
  static std::shared_ptr<Config> createShared() {
    return std::make_shared<Config>();
  }
  
  virtual ~Config(){
    tls_config_free(m_config);
  }
  
  TLSConfig getTLSConfig() {
    return m_config;
  }
  
};
  
}}

#endif /* oatpp_libressl_Config_hpp */
