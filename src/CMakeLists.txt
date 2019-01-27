
add_library(${OATPP_THIS_MODULE_NAME}
        oatpp-libressl/Callbacks.cpp
        oatpp-libressl/Callbacks.hpp
        oatpp-libressl/Config.cpp
        oatpp-libressl/Config.hpp
        oatpp-libressl/Connection.cpp
        oatpp-libressl/Connection.hpp
        oatpp-libressl/client/ConnectionProvider.cpp
        oatpp-libressl/client/ConnectionProvider.hpp
        oatpp-libressl/server/ConnectionProvider.cpp
        oatpp-libressl/server/ConnectionProvider.hpp
)

set_target_properties(${OATPP_THIS_MODULE_NAME} PROPERTIES
        CXX_STANDARD 11
        CXX_EXTENSIONS OFF
        CXX_STANDARD_REQUIRED ON
)

if(OATPP_MODULES_LOCATION STREQUAL OATPP_MODULES_LOCATION_EXTERNAL)
    add_dependencies(${OATPP_THIS_MODULE_NAME} ${LIB_OATPP_EXTERNAL})
endif()

target_link_oatpp(${OATPP_THIS_MODULE_NAME})

target_include_directories(${OATPP_THIS_MODULE_NAME}
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

target_include_directories(${OATPP_THIS_MODULE_NAME}
        PUBLIC ${PKG_TLS_INCLUDE_DIRS}
        PUBLIC ${PKG_SSL_INCLUDE_DIRS}
        PUBLIC ${PKG_CRYPTO_INCLUDE_DIRS}
)

#target_link_directories(${OATPP_THIS_MODULE_NAME}
#        PRIVATE ${PKG_TLS_LIBRARY_DIRS}
#        PRIVATE ${PKG_SSL_LIBRARY_DIRS}
#        PRIVATE ${PKG_CRYPTO_LIBRARY_DIRS}
#)

target_link_libraries(${OATPP_THIS_MODULE_NAME}
        PRIVATE ${PKG_TLS_LIBRARIES}
        PRIVATE ${PKG_SSL_LIBRARIES}
        PRIVATE ${PKG_CRYPTO_LIBRARIES}
)

#######################################################################################################
## install targets

if(OATPP_INSTALL)
    include("../cmake/module-install.cmake")
endif()
