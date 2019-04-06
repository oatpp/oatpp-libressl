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

#ifndef oatpp_libressl_Config_hpp
#define oatpp_libressl_Config_hpp

#include "oatpp/core/Types.hpp"

#include <tls.h>
#include <memory>

namespace oatpp { namespace libressl {

/**
 * Wrapper over `tls_config`.
 */
class Config {
public:
  typedef struct tls_config* TLSConfig;
private:
  TLSConfig m_config;
public:
  /**
   * Constructor.
   */
  Config();
public:

  /**
   * Create shared Config.
   * @return - `std::shared_ptr` to Config.
   */
  static std::shared_ptr<Config> createShared();

  /**
   * Create default config for server with enabled TLS.
   * @param keyFile - path to file with private key.
   * @param certFile - path to file with certificate.
   * @return - `std::shared_ptr` to Config.
   */
  static std::shared_ptr<Config> createDefaultServerConfig(const oatpp::String& keyFile, const oatpp::String& certFile);

  /**
   * Virtual destructor.
   */
  virtual ~Config();

  /**
   * Get underlying tls_config.
   * @return - `tls_config*`.
   */
  TLSConfig getTLSConfig();
  
};
  
}}

#endif /* oatpp_libressl_Config_hpp */
