cmake_minimum_required(VERSION 3.10)

include(GNUInstallDirs)

project(varmsg
	VERSION 0.1
    DESCRIPTION "Variable Message Generator"
)

add_executable( ${PROJECT_NAME}
	src/varmsg.c
)

target_include_directories( ${PROJECT_NAME}
	PRIVATE inc
)

target_link_libraries( ${PROJECT_NAME}
	${CMAKE_THREAD_LIBS_INIT}
	rt
	tjson
	varserver
)

install(TARGETS ${PROJECT_NAME}
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
