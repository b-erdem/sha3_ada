with Interfaces;

package body SHA3.Keccak is

   pragma SPARK_Mode;

   function Rotate_Left_64 (Value : U64; Amount : Natural) return U64 is
     (if Amount = 0 then Value
      else Interfaces.Shift_Left (Value, Amount)
           or Interfaces.Shift_Right (Value, 64 - Amount))
     with Pre => Amount >= 0 and then Amount < 64;

   RC : constant array (0 .. 23) of U64 :=
     [16#0000_0000_0000_0001#, 16#0000_0000_0000_8082#,
      16#8000_0000_0000_808A#, 16#8000_0000_8000_8000#,
      16#0000_0000_0000_808B#, 16#0000_0000_8000_0001#,
      16#8000_0000_8000_8081#, 16#8000_0000_0000_8009#,
      16#0000_0000_0000_008A#, 16#0000_0000_0000_0088#,
      16#0000_0000_8000_8009#, 16#0000_0000_8000_000A#,
      16#0000_0000_8000_808B#, 16#8000_0000_0000_008B#,
      16#8000_0000_0000_8089#, 16#8000_0000_0000_8003#,
      16#8000_0000_0000_8002#, 16#8000_0000_0000_0080#,
      16#0000_0000_0000_800A#, 16#8000_0000_8000_000A#,
      16#8000_0000_8000_8081#, 16#8000_0000_0000_8080#,
      16#0000_0000_8000_0001#, 16#8000_0000_8000_8008#];

   Theta_Left  : constant array (0 .. 4) of Natural := [4, 0, 1, 2, 3];
   Theta_Right : constant array (0 .. 4) of Natural := [1, 2, 3, 4, 0];

   Rho_Pi_Dest : constant array (0 .. 24) of Natural :=
     [0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22,
      23, 8, 18, 3, 13, 14, 24, 9, 19, 4];

   Rho_Pi_Rot : constant array (0 .. 24) of Natural :=
     [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
      41, 45, 15, 21, 8, 18, 2, 61, 56, 14];

   Chi_N1 : constant array (0 .. 24) of Natural :=
     [1, 2, 3, 4, 0, 6, 7, 8, 9, 5, 11, 12, 13, 14, 10,
      16, 17, 18, 19, 15, 21, 22, 23, 24, 20];

   Chi_N2 : constant array (0 .. 24) of Natural :=
     [2, 3, 4, 0, 1, 7, 8, 9, 5, 6, 12, 13, 14, 10, 11,
      17, 18, 19, 15, 16, 22, 23, 24, 20, 21];

   procedure Permute (A : in out State_Array) is
      B : State_Array := [others => 0];
      C : array (0 .. 4) of U64 := [others => 0];
      D : array (0 .. 4) of U64 := [others => 0];
   begin
      for Round in 0 .. 23 loop
         pragma Loop_Invariant
           (for all I in 0 .. 24 => A (I) /= 0 or else A (I) = 0);

         for X in 0 .. 4 loop
            C (X) := A (X) xor A (X + 5) xor A (X + 10)
                     xor A (X + 15) xor A (X + 20);
         end loop;

         for X in 0 .. 4 loop
            D (X) := C (Theta_Left (X))
                     xor Rotate_Left_64 (C (Theta_Right (X)), 1);
         end loop;

         for X in 0 .. 4 loop
            for Y in 0 .. 4 loop
               A (X + 5 * Y) := A (X + 5 * Y) xor D (X);
            end loop;
         end loop;

         for I in 0 .. 24 loop
            B (Rho_Pi_Dest (I)) :=
              Rotate_Left_64 (A (I), Rho_Pi_Rot (I));
         end loop;

         for I in 0 .. 24 loop
            A (I) := B (I) xor ((not B (Chi_N1 (I)))
                                and B (Chi_N2 (I)));
         end loop;

         A (0) := A (0) xor RC (Round);
      end loop;
   end Permute;

end SHA3.Keccak;
