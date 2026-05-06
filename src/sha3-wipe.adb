package body SHA3.Wipe is

   pragma SPARK_Mode (On);

   procedure Wipe_Sponge_State (S : in out Sponge_State) is
   begin
      for I in S.State'Range loop
         pragma Loop_Invariant
           (for all J in S.State'First .. I - 1 => S.State (J) = 0);
         S.State (I) := 0;
      end loop;
      S.Byte_Pos  := 0;
      S.Squeezing := False;
   end Wipe_Sponge_State;

   procedure Wipe_Byte_Array (X : in out Byte_Array) is
   begin
      for I in X'Range loop
         pragma Loop_Invariant
           (for all J in X'First .. I - 1 => X (J) = 0);
         X (I) := 0;
      end loop;
   end Wipe_Byte_Array;

end SHA3.Wipe;
