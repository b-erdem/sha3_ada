with SHA3;
with Interfaces;
with Ada.Text_IO; use Ada.Text_IO;

procedure Test_SHA3 is

   use type Interfaces.Unsigned_8;

   Pass_Count : Natural := 0;
   Fail_Count : Natural := 0;

   Hex_Chars : constant array (0 .. 15) of Character :=
     "0123456789abcdef";

   function To_Hex (Data : SHA3.Byte_Array) return String is
      Result : String (1 .. Data'Length * 2);
      Pos    : Positive := 1;
   begin
      for I in Data'Range loop
         Result (Pos)     := Hex_Chars
           (Natural (Interfaces.Shift_Right (Data (I), 4)));
         Result (Pos + 1) := Hex_Chars
           (Natural (Data (I) and 16#0F#));
         Pos := Pos + 2;
      end loop;
      return Result;
   end To_Hex;

   function Str_To_Bytes (S : String) return SHA3.Byte_Array is
      Result : SHA3.Byte_Array (0 .. S'Length - 1);
   begin
      for I in S'Range loop
         Result (I - S'First) :=
           SHA3.U8 (Character'Pos (S (I)));
      end loop;
      return Result;
   end Str_To_Bytes;

   function Make_Input (Len : Natural) return SHA3.Byte_Array is
   begin
      if Len = 0 then
         declare
            Result : SHA3.Byte_Array (0 .. -1);
         begin
            return Result;
         end;
      else
         declare
            Result : SHA3.Byte_Array (0 .. Len - 1);
         begin
            for I in 0 .. Len - 1 loop
               Result (I) := SHA3.U8 (I mod 251);
            end loop;
            return Result;
         end;
      end if;
   end Make_Input;

   procedure Check (Label : String; Got, Expected : String) is
   begin
      if Got = Expected then
         Put_Line ("PASS: " & Label);
         Pass_Count := Pass_Count + 1;
      else
         Put_Line ("FAIL: " & Label);
         Put_Line ("  expected: " & Expected);
         Put_Line ("  got:      " & Got);
         Fail_Count := Fail_Count + 1;
      end if;
   end Check;

   procedure Check_SHA3_256_Pattern
     (Len : Natural; Expected : String)
   is
      Input : constant SHA3.Byte_Array := Make_Input (Len);
      Out32 : SHA3.Byte_Array_32;
   begin
      SHA3.SHA3_256 (Input, Out32);
      Check ("SHA3-256(pattern," & Len'Image & " bytes)",
             To_Hex (Out32), Expected);
   end Check_SHA3_256_Pattern;

   procedure Check_SHA3_512_Pattern
     (Len : Natural; Expected : String)
   is
      Input : constant SHA3.Byte_Array := Make_Input (Len);
      Out64 : SHA3.Byte_Array_64;
   begin
      SHA3.SHA3_512 (Input, Out64);
      Check ("SHA3-512(pattern," & Len'Image & " bytes)",
             To_Hex (Out64), Expected);
   end Check_SHA3_512_Pattern;

   procedure Check_SHAKE128_Pattern
     (Len : Natural; Out_Len : Natural; Expected : String)
   is
      Input : constant SHA3.Byte_Array := Make_Input (Len);
      Output : SHA3.Byte_Array (0 .. Out_Len - 1);
   begin
      SHA3.SHAKE128 (Input, Output);
      Check ("SHAKE128(pattern," & Len'Image & " bytes,"
             & Out_Len'Image & " out)",
             To_Hex (Output), Expected);
   end Check_SHAKE128_Pattern;

   procedure Check_SHAKE256_Pattern
     (Len : Natural; Out_Len : Natural; Expected : String)
   is
      Input : constant SHA3.Byte_Array := Make_Input (Len);
      Output : SHA3.Byte_Array (0 .. Out_Len - 1);
   begin
      SHA3.SHAKE256 (Input, Output);
      Check ("SHAKE256(pattern," & Len'Image & " bytes,"
             & Out_Len'Image & " out)",
             To_Hex (Output), Expected);
   end Check_SHAKE256_Pattern;

   procedure Check_SHA3_256_Incremental (Len : Natural) is
      Input : constant SHA3.Byte_Array := Make_Input (Len);
      One_Shot : SHA3.Byte_Array_32;
      Chunked  : SHA3.Byte_Array_32;
      S : SHA3.Sponge_State;
      Pos : Natural := Input'First;
   begin
      SHA3.SHA3_256 (Input, One_Shot);

      SHA3.Init (S, SHA3.SHA3_256_Rate, SHA3.SHA3_Domain);
      while Pos <= Input'Last loop
         declare
            Take : constant Natural :=
              Natural'Min ((Pos mod 17) + 1, Input'Last - Pos + 1);
         begin
            SHA3.Absorb (S, Input (Pos .. Pos + Take - 1));
            Pos := Pos + Take;
         end;
      end loop;
      SHA3.Squeeze (S, Chunked);

      Check ("SHA3-256 incremental pattern" & Len'Image,
             To_Hex (Chunked), To_Hex (One_Shot));
   end Check_SHA3_256_Incremental;

   procedure Check_SHAKE256_Incremental
     (Len : Natural; Out_Len : Positive)
   is
      Input : constant SHA3.Byte_Array := Make_Input (Len);
      One_Shot : SHA3.Byte_Array (0 .. Out_Len - 1);
      Chunked  : SHA3.Byte_Array (0 .. Out_Len - 1);
      S : SHA3.Sponge_State;
      In_Pos  : Natural := Input'First;
      Out_Pos : Natural := Chunked'First;
   begin
      SHA3.SHAKE256 (Input, One_Shot);

      SHA3.Init (S, SHA3.SHAKE256_Rate, SHA3.SHAKE_Domain);
      while In_Pos <= Input'Last loop
         declare
            Take : constant Natural :=
              Natural'Min ((In_Pos mod 23) + 1, Input'Last - In_Pos + 1);
         begin
            SHA3.Absorb (S, Input (In_Pos .. In_Pos + Take - 1));
            In_Pos := In_Pos + Take;
         end;
      end loop;

      while Out_Pos <= Chunked'Last loop
         declare
            Take : constant Natural :=
              Natural'Min ((Out_Pos mod 29) + 1, Chunked'Last - Out_Pos + 1);
         begin
            SHA3.Squeeze (S, Chunked (Out_Pos .. Out_Pos + Take - 1));
            Out_Pos := Out_Pos + Take;
         end;
      end loop;

      Check ("SHAKE256 incremental pattern" & Len'Image
             & " out" & Out_Len'Image,
             To_Hex (Chunked), To_Hex (One_Shot));
   end Check_SHAKE256_Incremental;

   H32 : SHA3.Byte_Array_32;
   H64 : SHA3.Byte_Array_64;

begin
   Put_Line ("=== SHA-3/SHAKE Test Suite ===");
   New_Line;

   Put_Line ("--- SHA3-256 NIST KAT ---");
   New_Line;

   declare
      Empty : SHA3.Byte_Array (0 .. -1);
   begin
      SHA3.SHA3_256 (Empty, H32);
      Check ("SHA3-256(empty)",
             To_Hex (H32),
             "a7ffc6f8bf1ed76651c14756a061d662"
             & "f580ff4de43b49fa82d80a4b80f8434a");
   end;

   declare
      Input : constant SHA3.Byte_Array := Str_To_Bytes ("abc");
   begin
      SHA3.SHA3_256 (Input, H32);
      Check ("SHA3-256(abc)",
             To_Hex (H32),
             "3a985da74fe225b2045c172d6bd390bd"
             & "855f086e3e9d525b46bfe24511431532");
   end;

   declare
      Input : constant SHA3.Byte_Array :=
        Str_To_Bytes
          ("abcdbcdecdefdefgefghfghighijhijk"
           & "ijkljklmklmnlmnomnopnopq");
   begin
      SHA3.SHA3_256 (Input, H32);
      Check ("SHA3-256(56-byte NIST)",
             To_Hex (H32),
             "41c0dba2a9d6240849100376a8235e2c"
             & "82e1b9998a999e21db32dd97496d3376");
   end;

   New_Line;
   Put_Line ("--- SHA3-512 NIST KAT ---");
   New_Line;

   declare
      Empty : SHA3.Byte_Array (0 .. -1);
   begin
      SHA3.SHA3_512 (Empty, H64);
      Check ("SHA3-512(empty)",
             To_Hex (H64),
             "a69f73cca23a9ac5c8b567dc185a756e"
             & "97c982164fe25859e0d1dcc1475c80a6"
             & "15b2123af1f5f94c11e3e9402c3ac558"
             & "f500199d95b6d3e301758586281dcd26");
   end;

   declare
      Input : constant SHA3.Byte_Array := Str_To_Bytes ("abc");
   begin
      SHA3.SHA3_512 (Input, H64);
      Check ("SHA3-512(abc)",
             To_Hex (H64),
             "b751850b1a57168a5693cd924b6b096e"
             & "08f621827444f70d884f5d0240d2712e"
             & "10e116e9192af3c91a7ec57647e39340"
             & "57340b4cf408d5a56592f8274eec53f0");
   end;

   New_Line;
   Put_Line ("--- SHAKE128 NIST KAT ---");
   New_Line;

   declare
      Empty : SHA3.Byte_Array (0 .. -1);
      Out0 : SHA3.Byte_Array (0 .. -1);
      Out32 : SHA3.Byte_Array (0 .. 31);
   begin
      SHA3.SHAKE128 (Empty, Out0);
      Check ("SHAKE128(empty, 0)", To_Hex (Out0), "");

      SHA3.SHAKE128 (Empty, Out32);
      Check ("SHAKE128(empty, 256)",
             To_Hex (Out32),
             "7f9c2ba4e88f827d616045507605853e"
             & "d73b8093f6efbc88eb1a6eacfa66ef26");
   end;

   New_Line;
   Put_Line ("--- SHAKE256 NIST KAT ---");
   New_Line;

   declare
      Empty : SHA3.Byte_Array (0 .. -1);
      Out0 : SHA3.Byte_Array (0 .. -1);
      Out32 : SHA3.Byte_Array (0 .. 31);
   begin
      SHA3.SHAKE256 (Empty, Out0);
      Check ("SHAKE256(empty, 0)", To_Hex (Out0), "");

      SHA3.SHAKE256 (Empty, Out32);
      Check ("SHAKE256(empty, 256)",
             To_Hex (Out32),
             "46b9dd2b0ba88d13233b3feb743eeb24"
             & "3fcd52ea62b81b82b50c27646ed5762f");
   end;

   New_Line;
   Put_Line ("--- Multi-block Consistency ---");
   New_Line;

   declare
      Input_200 : constant SHA3.Byte_Array := Make_Input (200);
      Input_1k  : constant SHA3.Byte_Array := Make_Input (1000);
   begin
      SHA3.SHA3_256 (Input_200, H32);
      SHA3.SHA3_256 (Input_1k, H64 (0 .. 31));

      declare
         S : SHA3.Sponge_State;
         R : SHA3.Byte_Array_32;
      begin
         SHA3.Init (S, SHA3.SHA3_256_Rate, SHA3.SHA3_Domain);
         SHA3.Absorb (S, Input_200 (0 .. 99));
         SHA3.Absorb (S, Input_200 (100 .. 199));
         SHA3.Squeeze (S, R);
         Check ("inc vs one-shot (200 bytes)",
                To_Hex (R), To_Hex (H32));
      end;

      declare
         S : SHA3.Sponge_State;
         R : SHA3.Byte_Array_32;
      begin
         SHA3.Init (S, SHA3.SHA3_256_Rate, SHA3.SHA3_Domain);
         SHA3.Absorb (S, Input_1k (0 .. 499));
         SHA3.Absorb (S, Input_1k (500 .. 999));
         SHA3.Squeeze (S, R);
         Check ("inc vs one-shot (1k bytes)",
                To_Hex (R), To_Hex (H64 (0 .. 31)));
      end;
   end;

   New_Line;
   Put_Line ("--- Incremental SHAKE Consistency ---");
   New_Line;

   declare
      Input : constant SHA3.Byte_Array := Str_To_Bytes ("abc");
      Out_1shot : SHA3.Byte_Array (0 .. 63);
      Out_2part : SHA3.Byte_Array (0 .. 63);
      S : SHA3.Sponge_State;
   begin
      SHA3.SHAKE256 (Input, Out_1shot);

      SHA3.Init (S, SHA3.SHAKE256_Rate, SHA3.SHAKE_Domain);
      SHA3.Absorb (S, Input (0 .. 1));
      SHA3.Absorb (S, Input (2 .. 2));
      SHA3.Squeeze (S, Out_2part (0 .. 31));
      SHA3.Squeeze (S, Out_2part (32 .. 63));

      Check ("SHAKE256 one-shot vs inc",
             To_Hex (Out_2part), To_Hex (Out_1shot));
   end;

   New_Line;
   Put_Line ("--- Python hashlib Differential Vectors ---");
   New_Line;

   Check_SHA3_256_Pattern
     (1, "5d53469f20fef4f8eab52b88044ede69"
         & "c77a6a68a60728609fc4a65ff531e7d0");
   Check_SHA3_256_Pattern
     (135, "fded8fd9d6551c601eeb3b7c6bc5e5cf"
           & "d8aad1d015b7e9aaa9c9b9475231d5e2");
   Check_SHA3_256_Pattern
     (136, "cf3ccff92480a29160c2d38317c430e1"
           & "4749bfee1788106957dfe73f8c4930e5");
   Check_SHA3_256_Pattern
     (137, "ce9d7dc90913ee5d92745019479a5352"
           & "c6d6279bef18ed07dc0a83ee8084daca");
   Check_SHA3_256_Pattern
     (4096, "40e655a0042c7fc243710579c0d6fad0"
            & "5daceba7d474de35cccb17d194c2cda2");

   Check_SHA3_512_Pattern
     (71, "3ccc850d53a1287af7b4560b2ef0d43e"
          & "b5d9a80d62a0e9cf1dbc040135921104"
          & "d4395168e90bfc871773ebb34bca1bd6"
          & "7056e1cc7dc7a48ff7c3167d389f117c");
   Check_SHA3_512_Pattern
     (72, "5d63f2bbe971a983ac6847480106e4e1"
          & "264ee3a0befd79954914e1d86e795b2e"
          & "18238f12fc5e46cb9cc78efdec610a93"
          & "647cc04e1c23d8caaa6a58c21dd26c07");
   Check_SHA3_512_Pattern
     (73, "921d9b7b2b0f3066a1646dbb058c979c"
          & "b3925dec0f8c269faaa7f9648e73465a"
          & "e55ec527257d5d5e1cfdbf5d6799bea"
          & "1004b6186f5108c74e3b92fe924166558");
   Check_SHA3_512_Pattern
     (4096, "ac8fc5c0a7dc20b9234524accd6000bc"
            & "afbad2850a66455600873c13d1cb6875"
            & "824f6888630829896eb411ee4973896e"
            & "0fb6487d8be89fcc3dfd9eed6c93fe90");

   Check_SHAKE128_Pattern
     (1, 32, "0b784469a0628e03861cd8a196dfafa0"
             & "e9e8056d04cddcc49f0746b9ad43ccb2");
   Check_SHAKE128_Pattern
     (167, 64, "1e552791cc4e93a0d4a8dc47ae49228c"
               & "2faa869e40e628f6ace477aec3f1ca7a"
               & "efe1c1245cf82c265168ad2985121aed"
               & "d72335ae1187a36742c746cf2b40cb30");
   Check_SHAKE128_Pattern
     (168, 64, "f15277eb61c4908d44a2853f3cde071a"
               & "e2ed7a23461fbe162a1a98cf6875059c"
               & "06ffeebfca31afd9976e5592a3e7e5e"
               & "94a665a8befa4b64a7f089cc0f3572403");
   Check_SHAKE128_Pattern
     (169, 200, "015be3338c986d9846affa0f94b4afc2"
                & "a76bc289c709e1a596ec9eccf090a773"
                & "e4d69101b3a0516bfc556ffb886673b4"
                & "91f447926204119fed2933aea2d6091a"
                & "805c2509e9b3b0e6b2670a436c036049"
                & "ee97e003772876d06e184ab322b1ae89"
                & "9cfc605fec5edfe41642829a2dd3ec89"
                & "c66033ee5132ba179e99a0d9967d49ed"
                & "bd9e05f9887f10740f0808a20a1271f1"
                & "031a174dcfff1b6e14fec88077e01f87"
                & "c28944926abb73c38fa9579350f549a1"
                & "1966fd36750cba97b71d80572865466f"
                & "cd32822474be4a87");

   Check_SHAKE256_Pattern
     (1, 32, "b8d01df855f7075882c636f6ddeacf41"
             & "e5de0bbf30042ef0a86e36f4b8600d54");
   Check_SHAKE256_Pattern
     (135, 64, "c45dae624ad8a2f5aa7bac9d7557737f"
               & "d91c96eedb70a6be5574d57a844eade0"
               & "7f4056bf081a1098101cea8132188c42"
               & "2136feb4687d1e2209f3fd28bedfb8f4");
   Check_SHAKE256_Pattern
     (136, 64, "b7ff4073b3f5a8eabd6e17705ca7f676"
               & "1a31058f9df781a6a47e3a3063b9d67"
               & "a757e8dbf043dac48d2154e46d59c0b"
               & "9e8bc36ba035153691fbe83b9eff5dae4a");
   Check_SHAKE256_Pattern
     (137, 200, "01d90952c642a5eb2a8fc9d713f843a4"
                & "5d7ac05132dddcb2efc9bebc27e37bcb"
                & "e42130c36f3540250ab11796980e7736"
                & "83f28d07f0f838606fb9c45e452bd38"
                & "fb9ed42c8994cbad998a1971cf3d7bc"
                & "763f40cb04fefe876a20c27ece851d4"
                & "89539e1eaa5ecd62bb20bdad6526819"
                & "462c6e4efb71a45c5b46dd012647abd"
                & "1d899a03d1b514fb93828a21bc9368b"
                & "c24fe63808d6be567248bae61f38ba3"
                & "f9e676bbe8275ba47c2ff92d7704689"
                & "44b9933c96435488224af296b8b542f"
                & "9fd3dc0f9f8f23a3e654af44e");

   Check_SHA3_256_Incremental (0);
   Check_SHA3_256_Incremental (136);
   Check_SHA3_256_Incremental (4096);
   Check_SHAKE256_Incremental (0, 1);
   Check_SHAKE256_Incremental (137, 272);
   Check_SHAKE256_Incremental (4096, 512);

   New_Line;
   Put_Line ("=== Summary ===");
   Put_Line ("Pass:" & Pass_Count'Image & "  Fail:" & Fail_Count'Image);

end Test_SHA3;
