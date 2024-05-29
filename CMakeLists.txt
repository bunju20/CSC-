cmake_minimum_required(VERSION 3.12)
project(EncryptedVotingSystem)

# SEAL 라이브러리 경로 설정
set(SEAL_DIR "/Users/bunju/Git/CSC-HomomorphicEncryption/SEAL/build") # 실제 경로로 변경
find_package(SEAL REQUIRED PATHS ${SEAL_DIR} NO_DEFAULT_PATH)

add_executable(EncryptedVotingSystem ../sheet.cpp)

# SEAL 라이브러리 링크
target_link_libraries(EncryptedVotingSystem SEAL::seal)