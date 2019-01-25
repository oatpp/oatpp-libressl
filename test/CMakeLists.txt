add_executable(module-tests
        oatpp-libressl/tests.cpp
)

set_target_properties(module-tests PROPERTIES
        CXX_STANDARD 11
        CXX_EXTENSIONS OFF
        CXX_STANDARD_REQUIRED ON
)

target_include_directories(module-tests
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

if(OATPP_MODULES_LOCATION STREQUAL OATPP_MODULES_LOCATION_EXTERNAL)
    add_dependencies(module-tests ${LIB_OATPP_EXTERNAL})
endif()

add_dependencies(module-tests ${OATPP_THIS_MODULE_NAME})

if(TARGET oatpp::oatpp) ## OATPP_MODULES_LOCATION == INSTALLED

    message("Linking test executable to installed oatpp lib")

    target_link_libraries(${OATPP_THIS_MODULE_NAME}
            PRIVATE oatpp::oatpp
            PRIVATE oatpp::oatpp-test
    )

else()

    message("Linking test executable to found in provided path oatpp lib")

    target_include_directories(module-tests PUBLIC $<BUILD_INTERFACE:${OATPP_DIR_SRC}>)
    target_link_directories(module-tests PRIVATE ${OATPP_DIR_LIB})
    target_link_libraries(module-tests
            PRIVATE oatpp
            PRIVATE oatpp-test
    )

endif()

target_link_directories(module-tests
        PRIVATE ${PKG_TLS_LIBRARY_DIRS}
        PRIVATE ${PKG_SSL_LIBRARY_DIRS}
        PRIVATE ${PKG_CRYPTO_LIBRARY_DIRS}
)

target_link_libraries(module-tests
        PRIVATE ${OATPP_THIS_MODULE_NAME}
        PRIVATE ${PKG_TLS_LIBRARIES}
        PRIVATE ${PKG_SSL_LIBRARIES}
        PRIVATE ${PKG_CRYPTO_LIBRARIES}
)

add_test(module-tests module-tests)