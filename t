[1mdiff --git a/test/regression/aarch64/MicroOperation.cc b/test/regression/aarch64/MicroOperation.cc[m
[1mindex 8691b7c4..f5ec047c 100644[m
[1m--- a/test/regression/aarch64/MicroOperation.cc[m
[1m+++ b/test/regression/aarch64/MicroOperation.cc[m
[36m@@ -647,14 +647,30 @@[m [mTEST_P(MicroOp, storePairD) {[m
     stp d4, d5, [sp, #16][m
     stp d6, d7, [sp, #-16]![m
   )");[m
[36m-  EXPECT_EQ(getMemoryValue<double>(process_->getInitialProcessStackPointer() - 1024), -5.0);[m
[36m-  EXPECT_EQ(getMemoryValue<double>(process_->getInitialProcessStackPointer() - 1016), -3.5);[m
[36m-  EXPECT_EQ(getMemoryValue<double>(process_->getInitialProcessStackPointer() - 1008), 3.5);[m
[36m-  EXPECT_EQ(getMemoryValue<double>(process_->getInitialProcessStackPointer() - 1000), 5.0);[m
[36m-  EXPECT_EQ(getMemoryValue<double>(process_->getInitialProcessStackPointer() - 992), -1.5);[m
[36m-  EXPECT_EQ(getMemoryValue<double>(process_->getInitialProcessStackPointer() - 984), -0.5);[m
[36m-  EXPECT_EQ(getMemoryValue<double>(process_->getInitialProcessStackPointer() - 976), 0.5);[m
[36m-  EXPECT_EQ(getMemoryValue<double>(process_->getInitialProcessStackPointer() - 968), 1.5);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<double>(process_->getInitialProcessStackPointer() - 1024),[m
[32m+[m[32m      -5.0);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<double>(process_->getInitialProcessStackPointer() - 1016),[m
[32m+[m[32m      -3.5);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<double>(process_->getInitialProcessStackPointer() - 1008),[m
[32m+[m[32m      3.5);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<double>(process_->getInitialProcessStackPointer() - 1000),[m
[32m+[m[32m      5.0);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<double>(process_->getInitialProcessStackPointer() - 992),[m
[32m+[m[32m      -1.5);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<double>(process_->getInitialProcessStackPointer() - 984),[m
[32m+[m[32m      -0.5);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<double>(process_->getInitialProcessStackPointer() - 976),[m
[32m+[m[32m      0.5);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<double>(process_->getInitialProcessStackPointer() - 968),[m
[32m+[m[32m      1.5);[m
 }[m
 [m
 TEST_P(MicroOp, storePairQ) {[m
[36m@@ -694,38 +710,54 @@[m [mTEST_P(MicroOp, storePairQ) {[m
     stp q4, q5, [sp, #32][m
     stp q6, q7, [sp, #-32]![m
   )");[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1024),[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1024),[m
             0xABBACAFEABBACAFE);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1016),[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1016),[m
             0x1234567898765432);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1008),[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1008),[m
             0xABCDEFABCDEFABCD);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1000),[m
[36m-            0xCAFEABBACAFEABBA);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 992),[m
[36m-            0x9876543212345678);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 984),[m
[36m-            0xFEDCBAFEDCBAFEDC);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 976),[m
[36m-            0xABBACAFEABBACAFE);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 968),[m
[36m-            0x1234567898765432);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 960),[m
[36m-            0x9876543212345678);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 952),[m
[36m-            0xFEDCBAFEDCBAFEDC);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 944),[m
[36m-            0xABBACAFEABBACAFE);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 936),[m
[36m-            0x1234567898765432);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 928),[m
[36m-            0xABBACAFEABBACAFE);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 920),[m
[36m-            0x1234567898765432);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 912),[m
[36m-            0xABCDEFABCDEFABCD);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 904),[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1000),[m
             0xCAFEABBACAFEABBA);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 992),[m
[32m+[m[32m      0x9876543212345678);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 984),[m
[32m+[m[32m      0xFEDCBAFEDCBAFEDC);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 976),[m
[32m+[m[32m      0xABBACAFEABBACAFE);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 968),[m
[32m+[m[32m      0x1234567898765432);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 960),[m
[32m+[m[32m      0x9876543212345678);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 952),[m
[32m+[m[32m      0xFEDCBAFEDCBAFEDC);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 944),[m
[32m+[m[32m      0xABBACAFEABBACAFE);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 936),[m
[32m+[m[32m      0x1234567898765432);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 928),[m
[32m+[m[32m      0xABBACAFEABBACAFE);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 920),[m
[32m+[m[32m      0x1234567898765432);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 912),[m
[32m+[m[32m      0xABCDEFABCDEFABCD);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 904),[m
[32m+[m[32m      0xCAFEABBACAFEABBA);[m
 }[m
 [m
 TEST_P(MicroOp, storePairS) {[m
[36m@@ -746,14 +778,30 @@[m [mTEST_P(MicroOp, storePairS) {[m
     stp s4, s5, [sp, #8][m
     stp s6, s7, [sp, #-8]![m
   )");[m
[36m-  EXPECT_EQ(getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1024), -5.0f);[m
[36m-  EXPECT_EQ(getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1020), -3.5f);[m
[36m-  EXPECT_EQ(getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1016), 3.5f);[m
[36m-  EXPECT_EQ(getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1012), 5.0f);[m
[36m-  EXPECT_EQ(getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1008), -1.5f);[m
[36m-  EXPECT_EQ(getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1004), -0.5f);[m
[36m-  EXPECT_EQ(getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1000), 0.5f);[m
[36m-  EXPECT_EQ(getMemoryValue<float>(process_->getInitialProcessStackPointer() - 996), 1.5f);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1024),[m
[32m+[m[32m      -5.0f);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1020),[m
[32m+[m[32m      -3.5f);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1016),[m
[32m+[m[32m      3.5f);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1012),[m
[32m+[m[32m      5.0f);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1008),[m
[32m+[m[32m      -1.5f);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1004),[m
[32m+[m[32m      -0.5f);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1000),[m
[32m+[m[32m      0.5f);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<float>(process_->getInitialProcessStackPointer() - 996),[m
[32m+[m[32m      1.5f);[m
 }[m
 [m
 TEST_P(MicroOp, storePairW) {[m
[36m@@ -774,14 +822,30 @@[m [mTEST_P(MicroOp, storePairW) {[m
     stp w4, w5, [sp, #8][m
     stp w6, w7, [sp, #-8]![m
   )");[m
[36m-  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() - 1024), 12);[m
[36m-  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() - 1020), 24);[m
[36m-  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() - 1016), 84);[m
[36m-  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() - 1012), 96);[m
[36m-  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() - 1008), 36);[m
[36m-  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() - 1004), 48);[m
[36m-  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() - 1000), 60);[m
[36m-  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() - 996), 72);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1024),[m
[32m+[m[32m            12);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1020),[m
[32m+[m[32m            24);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1016),[m
[32m+[m[32m            84);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1012),[m
[32m+[m[32m            96);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1008),[m
[32m+[m[32m            36);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1004),[m
[32m+[m[32m            48);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1000),[m
[32m+[m[32m            60);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() - 996),[m
[32m+[m[32m      72);[m
 }[m
 [m
 TEST_P(MicroOp, storePairX) {[m
[36m@@ -802,14 +866,30 @@[m [mTEST_P(MicroOp, storePairX) {[m
     stp x4, x5, [sp, #16][m
     stp x6, x7, [sp, #-16]![m
   )");[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1024), 12);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1016), 24);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1008), 84);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1000), 96);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 992), 36);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 984), 48);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 976), 60);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 968), 72);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1024),[m
[32m+[m[32m            12);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1016),[m
[32m+[m[32m            24);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1008),[m
[32m+[m[32m            84);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1000),[m
[32m+[m[32m            96);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 992),[m
[32m+[m[32m      36);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 984),[m
[32m+[m[32m      48);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 976),[m
[32m+[m[32m      60);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 968),[m
[32m+[m[32m      72);[m
 }[m
 [m
 TEST_P(MicroOp, storeB) {[m
[36m@@ -837,10 +917,18 @@[m [mTEST_P(MicroOp, storeB) {[m
     str b2, [sp, #1][m
     str b3, [sp, #-1]![m
   )");[m
[36m-  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getInitialProcessStackPointer() - 1024), 0xAB);[m
[36m-  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getInitialProcessStackPointer() - 1023), 0xFE);[m
[36m-  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getInitialProcessStackPointer() - 1022), 0xBA);[m
[36m-  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getInitialProcessStackPointer() - 1021), 0xCA);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint8_t>(process_->getInitialProcessStackPointer() - 1024),[m
[32m+[m[32m      0xAB);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint8_t>(process_->getInitialProcessStackPointer() - 1023),[m
[32m+[m[32m      0xFE);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint8_t>(process_->getInitialProcessStackPointer() - 1022),[m
[32m+[m[32m      0xBA);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint8_t>(process_->getInitialProcessStackPointer() - 1021),[m
[32m+[m[32m      0xCA);[m
 }[m
 [m
 TEST_P(MicroOp, storeD) {[m
[36m@@ -857,10 +945,18 @@[m [mTEST_P(MicroOp, storeD) {[m
     str d2, [sp, #8][m
     str d3, [sp, #-8]![m
   )");[m
[36m-  EXPECT_EQ(getMemoryValue<double>(process_->getInitialProcessStackPointer() - 1024), -3.0);[m
[36m-  EXPECT_EQ(getMemoryValue<double>(process_->getInitialProcessStackPointer() - 1016), 3.0);[m
[36m-  EXPECT_EQ(getMemoryValue<double>(process_->getInitialProcessStackPointer() - 1008), -1.5);[m
[36m-  EXPECT_EQ(getMemoryValue<double>(process_->getInitialProcessStackPointer() - 1000), 1.5);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<double>(process_->getInitialProcessStackPointer() - 1024),[m
[32m+[m[32m      -3.0);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<double>(process_->getInitialProcessStackPointer() - 1016),[m
[32m+[m[32m      3.0);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<double>(process_->getInitialProcessStackPointer() - 1008),[m
[32m+[m[32m      -1.5);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<double>(process_->getInitialProcessStackPointer() - 1000),[m
[32m+[m[32m      1.5);[m
 }[m
 [m
 TEST_P(MicroOp, storeH) {[m
[36m@@ -888,13 +984,17 @@[m [mTEST_P(MicroOp, storeH) {[m
     str h2, [sp, #2][m
     str h3, [sp, #-2]![m
   )");[m
[36m-  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getInitialProcessStackPointer() - 1024),[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1024),[m
             0xABBA);[m
[36m-  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getInitialProcessStackPointer() - 1022),[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1022),[m
             0x5678);[m
[36m-  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getInitialProcessStackPointer() - 1020),[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1020),[m
             0xCAFE);[m
[36m-  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getInitialProcessStackPointer() - 1018),[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1018),[m
             0x1234);[m
 }[m
 [m
[36m@@ -927,22 +1027,30 @@[m [mTEST_P(MicroOp, storeQ) {[m
     str q2, [sp, #16][m
     str q3, [sp, #-16]![m
   )");[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1024),[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1024),[m
             0xABBACAFEABBACAFE);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1016),[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1016),[m
             0x1234567898765432);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1008),[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1008),[m
             0xABBACAFEABBACAFE);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1000),[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1000),[m
             0x1234567898765432);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 992),[m
[36m-            0xABCDEFABCDEFABCD);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 984),[m
[36m-            0xCAFEABBACAFEABBA);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 976),[m
[36m-            0x9876543212345678);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 968),[m
[36m-            0xFEDCBAFEDCBAFEDC);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 992),[m
[32m+[m[32m      0xABCDEFABCDEFABCD);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 984),[m
[32m+[m[32m      0xCAFEABBACAFEABBA);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 976),[m
[32m+[m[32m      0x9876543212345678);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 968),[m
[32m+[m[32m      0xFEDCBAFEDCBAFEDC);[m
 }[m
 [m
 TEST_P(MicroOp, storeS) {[m
[36m@@ -959,10 +1067,18 @@[m [mTEST_P(MicroOp, storeS) {[m
     str s2, [sp, #4][m
     str s3, [sp, #-4]![m
   )");[m
[36m-  EXPECT_EQ(getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1024), -3.0f);[m
[36m-  EXPECT_EQ(getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1020), 3.0f);[m
[36m-  EXPECT_EQ(getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1016), -1.5f);[m
[36m-  EXPECT_EQ(getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1012), 1.5f);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1024),[m
[32m+[m[32m      -3.0f);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1020),[m
[32m+[m[32m      3.0f);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1016),[m
[32m+[m[32m      -1.5f);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<float>(process_->getInitialProcessStackPointer() - 1012),[m
[32m+[m[32m      1.5f);[m
 }[m
 [m
 TEST_P(MicroOp, storeW) {[m
[36m@@ -979,10 +1095,18 @@[m [mTEST_P(MicroOp, storeW) {[m
     str w2, [sp, #4][m
     str w3, [sp, #-4]![m
   )");[m
[36m-  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() - 1024), 12);[m
[36m-  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() - 1020), 48);[m
[36m-  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() - 1016), 24);[m
[36m-  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() - 1012), 36);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1024),[m
[32m+[m[32m            12);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1020),[m
[32m+[m[32m            48);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1016),[m
[32m+[m[32m            24);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1012),[m
[32m+[m[32m            36);[m
 }[m
 [m
 TEST_P(MicroOp, storeX) {[m
[36m@@ -999,10 +1123,18 @@[m [mTEST_P(MicroOp, storeX) {[m
     str x2, [sp, #8][m
     str x3, [sp, #-8]![m
   )");[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1024), 12);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1016), 48);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1008), 24);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1000), 36);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1024),[m
[32m+[m[32m            12);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1016),[m
[32m+[m[32m            48);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1008),[m
[32m+[m[32m            24);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1000),[m
[32m+[m[32m            36);[m
 }[m
 [m
 TEST_P(MicroOp, storeThenLoad) {[m
[36m@@ -1026,10 +1158,18 @@[m [mTEST_P(MicroOp, storeThenLoad) {[m
     ldr x7, [sp, #8][m
     ldr x8, [sp, #-8]![m
   )");[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1024), 12);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1016), 48);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1008), 24);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1000), 36);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1024),[m
[32m+[m[32m            12);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1016),[m
[32m+[m[32m            48);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1008),[m
[32m+[m[32m            24);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1000),[m
[32m+[m[32m            36);[m
   EXPECT_EQ(getGeneralRegister<uint64_t>(5), 12);[m
   EXPECT_EQ(getGeneralRegister<uint64_t>(6), 24);[m
   EXPECT_EQ(getGeneralRegister<uint64_t>(7), 36);[m
[36m@@ -1061,14 +1201,30 @@[m [mTEST_P(MicroOp, storeThenLoadPair) {[m
     ldp x12, x13, [sp, #16][m
     ldp x14, x15, [sp, #-16]![m
   )");[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1024), 12);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1016), 24);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1008), 84);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 1000), 96);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 992), 36);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 984), 48);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 976), 60);[m
[36m-  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 968), 72);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1024),[m
[32m+[m[32m            12);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1016),[m
[32m+[m[32m            24);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1008),[m
[32m+[m[32m            84);[m
[32m+[m[32m  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() -[m
[32m+[m[32m                                     1000),[m
[32m+[m[32m            96);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 992),[m
[32m+[m[32m      36);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 984),[m
[32m+[m[32m      48);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 976),[m
[32m+[m[32m      60);[m
[32m+[m[32m  EXPECT_EQ([m
[32m+[m[32m      getMemoryValue<uint64_t>(process_->getInitialProcessStackPointer() - 968),[m
[32m+[m[32m      72);[m
   EXPECT_EQ(getGeneralRegister<uint64_t>(8), 12);[m
   EXPECT_EQ(getGeneralRegister<uint64_t>(9), 24);[m
   EXPECT_EQ(getGeneralRegister<uint64_t>(10), 36);[m
