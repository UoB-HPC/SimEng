#include <fcntl.h>

#include "gtest/gtest.h"
#include "simeng/kernel/Vma.hh"
#include "simeng/version.hh"

using namespace simeng::kernel;

namespace {
TEST(VmaTest, VmaCreationWithoutFileBuf) {
  VirtualMemoryArea* vma = new VirtualMemoryArea(0, 0, 0, NULL);
  ASSERT_EQ(vma->getFileBuf(), nullptr);
  ASSERT_EQ(vma->getFileSize(), 0);
}

TEST(VmaTest, VmaHasFile) {
  VirtualMemoryArea* vma = new VirtualMemoryArea(0, 0, 0, NULL);
  ASSERT_EQ(vma->hasFile(), false);
}

TEST(VmaTest, VmaOverlaps) {
  VirtualMemoryArea* vma = new VirtualMemoryArea(0, 0, 4096, NULL);
  vma->vmStart_ = 0;
  vma->vmEnd_ = 4096;
  ASSERT_EQ(vma->hasFile(), false);
  /*
   Case 1 - Overlap
   [---------------------------------)
   [---------]
  */
  ASSERT_EQ(vma->overlaps(0, 300), true);
  /*
   Case 2 - No Overlap (Address ranges are not inclusive of end address)
   [------------)
                [-------------]
  */
  ASSERT_EQ(vma->overlaps(4096, 4096), false);
  /*
   Case 3 - Overlap
   [---------------------------------)
              [----------------------]
  */
  ASSERT_EQ(vma->overlaps(1000, 4095), true);
  /*
   Case 4 - Overlap
   [-------------------------------)
            [-------------------------]
  */
  ASSERT_EQ(vma->overlaps(1000, 4096), true);

  vma->vmStart_ = 4096;
  vma->vmEnd_ = 8192;
  /*
   Case 5 - Overlap
             [---------------------)
   [----------------]
  */
  ASSERT_EQ(vma->overlaps(1024, 4096), true);
  /*
     Case 6 - Overlap
               [-------------)
     [---------]
    */
  ASSERT_EQ(vma->overlaps(1024, 3072), true);
  /*
     Case 7 - No Overlap
                [------------)
     [---------]
    */
  ASSERT_EQ(vma->overlaps(1024, 3071), false);
  /*
     Case 8 - Overlap
     [---------------------------------)
     [---------------------------------]
    */
  ASSERT_EQ(vma->overlaps(4096, 4095), true);
  /*
     Case 9 - Overlap
     [---------------------------------)
     [------------------------------------]
    */
  ASSERT_EQ(vma->overlaps(4096, 10000), true);
  /*
     Case 10 - Overlap
     [---------------------------------)
               [---------]
    */
  ASSERT_EQ(vma->overlaps(4192, 400), true);
}

TEST(VmaTest, VmaContainsAddrRange) {
  VirtualMemoryArea* vma = new VirtualMemoryArea(0, 0, 4096, NULL);
  vma->vmStart_ = 0;
  vma->vmEnd_ = 4096;
  ASSERT_EQ(vma->hasFile(), false);
  /*
   Case 1 - Contains
   [---------------------------------)
   [---------]
  */
  ASSERT_EQ(vma->contains(0, 300), true);
  /*
   Case 2 - Doesn't Contains
   [------------)
                [-------------]
  */
  ASSERT_EQ(vma->contains(4096, 4096), false);
  /*
   Case 3 - Contains
   [---------------------------------)
              [---------------------]
  */
  ASSERT_EQ(vma->contains(1000, 3095), true);
  /*
   Case 4 - Doesn't Contain
   [---------------------------------)
            [---------------------------]
  */
  ASSERT_EQ(vma->contains(1000, 4096), false);

  vma->vmStart_ = 4096;
  vma->vmEnd_ = 8192;
  /*
   Case 5 - Doesn't Contain
             [---------------------)
   [----------------]
  */
  ASSERT_EQ(vma->contains(1024, 4096), false);
  /*
     Case 6 - Doesnt Contain
                [------------)
     [---------]
*/
  ASSERT_EQ(vma->contains(1024, 3071), false);
  /*
     Case 7 - Contains
     [---------------------------------)
     [---------------------------------]
    */
  ASSERT_EQ(vma->contains(4096, 4095), true);
  /*
     Case 8 - Contains
     [---------------------------------)
     [--------------------------------]
    */
  ASSERT_EQ(vma->contains(4096, 4096), true);
  /*
     Case 9 - Contains
     [---------------------------------)
               [---------]
    */
  ASSERT_EQ(vma->contains(4192, 400), true);
}

TEST(VmaTest, VmaContainsAddr) {
  VirtualMemoryArea* vma = new VirtualMemoryArea(0, 0, 4096, NULL);
  vma->vmStart_ = 4096;
  vma->vmEnd_ = 8192;

  ASSERT_EQ(vma->contains(4096), true);
  ASSERT_EQ(vma->contains(8191), true);
  ASSERT_EQ(vma->contains(5124), true);
  ASSERT_EQ(vma->contains(8192), false);
  ASSERT_EQ(vma->contains(0), false);
  ASSERT_EQ(vma->contains(8193), false);
}

TEST(VmaTest, VmaContainedInRange) {
  VirtualMemoryArea* vma = new VirtualMemoryArea(0, 0, 4096, NULL);
  vma->vmStart_ = 4096;
  vma->vmEnd_ = 8192;
  /*
   Case 1 - Not Contained
   [--------]
   [---------)
  */
  ASSERT_EQ(vma->containedIn(4096, 3121), false);
  /*
   Case 2 - Not Contained
       [------------)
   [-------------]
  */
  ASSERT_EQ(vma->containedIn(3000, 4096), false);
  /*
   Case 3 - Not Contained
   [--------)
      [---- ]
  */
  ASSERT_EQ(vma->containedIn(5096, 3096), false);
  /*
   Case 4 - Not Contained
      [---------]
   [-----)
  */
  ASSERT_EQ(vma->containedIn(5096, 4096), false);

  /*
   Case 5 - Contained
   [------------]
      [------)
  */
  ASSERT_EQ(vma->containedIn(0, 12288), true);
  /*
     Case 6 - Contained
     [------------]
     [------------)
  */
  ASSERT_EQ(vma->containedIn(4096, 4096), true);
  /*
     Case 7 - Contained
     [------------]
        [---------)
    */
  ASSERT_EQ(vma->containedIn(3000, 5192), true);
  /*
     Case 8 - Contained
     [------------]
     [---------)
    */
  ASSERT_EQ(vma->containedIn(4096, 8192), true);
}

TEST(VmaTest, VmaTrimRangeStart) {
  VirtualMemoryArea* vma = new VirtualMemoryArea(0, 0, 4096, NULL);
  vma->vmStart_ = 4096;
  vma->vmEnd_ = 8192;

  ASSERT_EQ(vma->containedIn(5096, 3096), false);

  vma->trimRangeStart(5096);

  ASSERT_EQ(vma->vmStart_, 5096);
  ASSERT_EQ(vma->vmEnd_, 8192);
  ASSERT_EQ(vma->vmSize_, 3096);

  ASSERT_EQ(vma->containedIn(5096, 3096), true);
}

TEST(VmaTest, VmaTrimRangeEnd) {
  VirtualMemoryArea* vma = new VirtualMemoryArea(0, 0, 4096, NULL);
  vma->vmStart_ = 4096;
  vma->vmEnd_ = 8192;

  ASSERT_EQ(vma->containedIn(4096, 3096), false);

  vma->trimRangeEnd(7192);

  ASSERT_EQ(vma->vmStart_, 4096);
  ASSERT_EQ(vma->vmEnd_, 7192);
  ASSERT_EQ(vma->vmSize_, 3096);

  ASSERT_EQ(vma->containedIn(4096, 3096), true);
}

TEST(VmaTest, CreateVmaWithHostedFileMMap) {
  HostBackedFileMMaps hbfmmap;
  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/unit/Data.txt";
  int fd = open(fpath.c_str(), O_RDWR);
  ASSERT_NE(fd, -1);

  HostFileMMap* fmap = hbfmmap.mapfd(fd, 21, 0);
  EXPECT_TRUE(fmap != NULL);

  VMA* vma = new VMA(0, 0, 4096, fmap);
  vma->vmStart_ = 4096;
  vma->vmEnd_ = 8192;

  ASSERT_TRUE(vma->hasFile());
  ASSERT_EQ(vma->getFileSize(), 21);

  std::string text = "FileDescArrayTestData";
  char* ftext = new char[22];
  memset(ftext, '\0', 22);
  memcpy(ftext, vma->getFileBuf(), vma->getFileSize());
  ASSERT_EQ(text, std::string(ftext));

  ASSERT_NE(close(fd), -1);
  delete[] ftext;
}

TEST(VmaTest, VmaTrimRangeStartWithHostBackedFile) {
  HostBackedFileMMaps hbfmmap;
  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/unit/Data.txt";
  int fd = open(fpath.c_str(), O_RDWR);
  ASSERT_NE(fd, -1);

  HostFileMMap* fmap = hbfmmap.mapfd(fd, 21, 0);
  EXPECT_TRUE(fmap != NULL);

  VMA* vma = new VMA(0, 0, 4096, fmap);
  vma->vmStart_ = 4096;
  vma->vmEnd_ = 8192;

  ASSERT_TRUE(vma->hasFile());
  ASSERT_EQ(vma->getFileSize(), 21);

  std::string text = "FileDescArrayTestData";
  char* ftext = new char[22];
  memset(ftext, '\0', 22);
  memcpy(ftext, vma->getFileBuf(), vma->getFileSize());
  ASSERT_EQ(text, std::string(ftext));
  delete[] ftext;

  vma->trimRangeStart(4096 + 8);
  text = "ArrayTestData";
  ftext = new char[14];
  memset(ftext, '\0', 14);
  memcpy(ftext, vma->getFileBuf(), vma->getFileSize());
  ASSERT_EQ(vma->getFileSize(), 13);
  ASSERT_EQ(text, std::string(ftext));

  ASSERT_NE(close(fd), -1);
  delete[] ftext;
}

TEST(VmaTest, VmaTrimRangeEndWithHostBackedFile) {
  HostBackedFileMMaps hbfmmap;
  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/unit/Data.txt";
  int fd = open(fpath.c_str(), O_RDWR);
  ASSERT_NE(fd, -1);

  HostFileMMap* fmap = hbfmmap.mapfd(fd, 21, 0);
  EXPECT_TRUE(fmap != NULL);

  VMA* vma = new VMA(0, 0, 4096, fmap);
  vma->vmStart_ = 4096;
  vma->vmEnd_ = 8192;

  ASSERT_TRUE(vma->hasFile());
  ASSERT_EQ(vma->getFileSize(), 21);

  std::string text = "FileDescArrayTestData";
  char* ftext = new char[22];
  memset(ftext, '\0', 22);
  memcpy(ftext, vma->getFileBuf(), vma->getFileSize());
  ASSERT_EQ(text, std::string(ftext));
  delete[] ftext;

  vma->trimRangeEnd(4096 + 13);
  text = "FileDescArray";
  ftext = new char[14];
  memset(ftext, '\0', 14);
  memcpy(ftext, vma->getFileBuf(), vma->getFileSize());
  ASSERT_EQ(vma->getFileSize(), 13);
  ASSERT_EQ(text, std::string(ftext));

  ASSERT_NE(close(fd), -1);
}

}  // namespace
