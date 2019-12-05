
#include "oatpp-test/UnitTest.hpp"

#include "oatpp-libressl/client/ConnectionProvider.hpp"
#include "oatpp-libressl/server/ConnectionProvider.hpp"
#include "oatpp-libressl/Callbacks.hpp"

#include "oatpp/core/concurrency/SpinLock.hpp"
#include "oatpp/core/base/Environment.hpp"

#include <iostream>

namespace {

class Test : public oatpp::test::UnitTest {
public:
  Test() : oatpp::test::UnitTest("MyTag")
  {}

  void onRun() override {

    // TODO - create meaningful tests !!!

    auto config = oatpp::libressl::Config::createShared();

    try {
      auto serverConnectionProvider = oatpp::libressl::server::ConnectionProvider::createShared(config, 8000);
    } catch(...) {

    }

    auto clientConnectionProvider = oatpp::libressl::client::ConnectionProvider(config, "localhost", 8000);

  }
  
};

void runTests() {

  /* set lockingCallback for libressl */
  oatpp::libressl::Callbacks::setDefaultCallbacks();

  OATPP_RUN_TEST(Test);

}

}

int main() {

  oatpp::base::Environment::init();

  runTests();

  /* Print how much objects were created during app running, and what have left-probably leaked */
  /* Disable object counting for release builds using '-D OATPP_DISABLE_ENV_OBJECT_COUNTERS' flag for better performance */
  std::cout << "\nEnvironment:\n";
  std::cout << "objectsCount = " << oatpp::base::Environment::getObjectsCount() << "\n";
  std::cout << "objectsCreated = " << oatpp::base::Environment::getObjectsCreated() << "\n\n";

  OATPP_ASSERT(oatpp::base::Environment::getObjectsCount() == 0);

  oatpp::base::Environment::destroy();

  return 0;
}
