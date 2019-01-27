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

target_link_oatpp(module-tests)

#target_link_directories(module-tests
#        PRIVATE ${PKG_TLS_LIBRARY_DIRS}
#        PRIVATE ${PKG_SSL_LIBRARY_DIRS}
#        PRIVATE ${PKG_CRYPTO_LIBRARY_DIRS}
#)

target_link_libraries(module-tests
        PRIVATE ${OATPP_THIS_MODULE_NAME}
        PRIVATE ${PKG_TLS_LIBRARIES}
        PRIVATE ${PKG_SSL_LIBRARIES}
        PRIVATE ${PKG_CRYPTO_LIBRARIES}
)

add_test(module-tests module-tests)