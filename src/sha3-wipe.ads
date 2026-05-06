--  Memory wiping for SHA3 sponge state.
--
--  When SHA3 is used as a XOF or PRF on secret material (for example
--  by ML-KEM and SLH-DSA), the absorbed bytes live in the 200-byte
--  Keccak state until the calling procedure zeroes them. The Wipe
--  helpers here let callers do that explicitly.
--
--  The bodies are in a separate compilation unit and the spec carries
--  `Inline => False` so the compiler cannot see the body at the call
--  site and prove the writes dead. With -O2 and no whole-program LTO
--  this gives a robust zeroisation guarantee; if your build uses LTO,
--  pair with `-fno-builtin-memset` or call `explicit_bzero(3)`.

package SHA3.Wipe is

   pragma Pure;
   pragma SPARK_Mode;

   procedure Wipe_Sponge_State (S : in out Sponge_State)
     with Inline => False,
          Always_Terminates => True,
          Post => (for all I in 0 .. 24 => S.State (I) = 0)
                  and then S.Byte_Pos = 0
                  and then not S.Squeezing;

   procedure Wipe_Byte_Array (X : in out Byte_Array)
     with Inline => False,
          Always_Terminates => True,
          Post => (for all I in X'Range => X (I) = 0);

end SHA3.Wipe;
