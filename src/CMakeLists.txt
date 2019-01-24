
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

if(MODULE_WAIT_DEPS)
    add_dependencies(${OATPP_THIS_MODULE_NAME} ${LIB_oatpp})
endif()

target_include_directories(${OATPP_THIS_MODULE_NAME}
        PUBLIC $<BUILD_INTERFACE:${OATPP_DIR_SRC}/src>
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        PUBLIC $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>/oatpp-${OATPP_THIS_MODULE_VERSION}/${OATPP_THIS_MODULE_NAME}
)

target_include_directories(${OATPP_THIS_MODULE_NAME}
        PUBLIC ${PKG_TLS_INCLUDE_DIRS}
        PUBLIC ${PKG_SSL_INCLUDE_DIRS}
        PUBLIC ${PKG_CRYPTO_INCLUDE_DIRS}
)

target_link_directories(${OATPP_THIS_MODULE_NAME}
        PRIVATE ${OATPP_DIR_LIB}/src
        PRIVATE ${PKG_TLS_LIBRARY_DIRS}
        PRIVATE ${PKG_SSL_LIBRARY_DIRS}
        PRIVATE ${PKG_CRYPTO_LIBRARY_DIRS}
)

target_link_libraries(${OATPP_THIS_MODULE_NAME}
        PRIVATE oatpp
        PRIVATE oatpp-test
        PRIVATE ${PKG_TLS_LIBRARIES}
        PRIVATE ${PKG_SSL_LIBRARIES}
        PRIVATE ${PKG_CRYPTO_LIBRARIES}
)

#######################################################################################################
## INSTALL TARGETS

if(OATPP_INSTALL)
    include("oatpp-module-install.cmake")
endif()