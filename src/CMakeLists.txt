
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

if(OATPP_MODULES_LOCATION STREQUAL OATPP_MODULES_LOCATION_EXTERNAL)
    add_dependencies(${OATPP_THIS_MODULE_NAME} ${LIB_OATPP_EXTERNAL})
endif()

if(TARGET oatpp::oatpp) ## OATPP_MODULES_LOCATION == INSTALLED

    message("Linking library to installed oatpp lib")

    target_link_libraries(${OATPP_THIS_MODULE_NAME}
            PRIVATE oatpp::oatpp
            PRIVATE oatpp::oatpp-test
    )

    #target_include_directories(${OATPP_THIS_MODULE_NAME}
    #        PUBLIC $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>/oatpp-${OATPP_THIS_MODULE_VERSION}/oatpp ## main oatpp module
    #)

else()

    message("Linking library to found in provided path oatpp lib")

    target_include_directories(${OATPP_THIS_MODULE_NAME} PUBLIC $<BUILD_INTERFACE:${OATPP_DIR_SRC}>)
    target_link_directories(${OATPP_THIS_MODULE_NAME} PRIVATE ${OATPP_DIR_LIB})
    target_link_libraries(${OATPP_THIS_MODULE_NAME}
            PRIVATE oatpp
            PRIVATE oatpp-test
    )

endif()

target_include_directories(${OATPP_THIS_MODULE_NAME}
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

target_include_directories(${OATPP_THIS_MODULE_NAME}
        PUBLIC ${PKG_TLS_INCLUDE_DIRS}
        PUBLIC ${PKG_SSL_INCLUDE_DIRS}
        PUBLIC ${PKG_CRYPTO_INCLUDE_DIRS}
)

target_link_directories(${OATPP_THIS_MODULE_NAME}
        PRIVATE ${PKG_TLS_LIBRARY_DIRS}
        PRIVATE ${PKG_SSL_LIBRARY_DIRS}
        PRIVATE ${PKG_CRYPTO_LIBRARY_DIRS}
)

target_link_libraries(${OATPP_THIS_MODULE_NAME}
        PRIVATE ${PKG_TLS_LIBRARIES}
        PRIVATE ${PKG_SSL_LIBRARIES}
        PRIVATE ${PKG_CRYPTO_LIBRARIES}
)

#######################################################################################################
## INSTALL TARGETS

if(OATPP_INSTALL)
    include("module-install.cmake")
endif()