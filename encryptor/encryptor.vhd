LIBRARY IEEE;
USE IEEE.NUMERIC_STD.ALL;
USE IEEE.STD_LOGIC_1164.ALL;
USE STD.TEXTIO.ALL;

ENTITY ENCRYPTOR IS
	PORT(
		CLOCK, START, MODE	: IN STD_LOGIC								:= '0';
		HASH						: IN STD_LOGIC_VECTOR(7 DOWNTO 0)	:= "00000000"
	);
END ENTITY;

ARCHITECTURE ALGORITHM OF ENCRYPTOR IS
	FILE DEC											: TEXT;
	FILE ENC											: TEXT;
	
--------------------------------------------------------------------------------
--Ubah nilai N sesuai dengan panjang password yang ingin di-encrypt atau di-
--decrypt.
--------------------------------------------------------------------------------

	SIGNAL N											: INTEGER							:= 16;

--------------------------------------------------------------------------------
	
--------------------------------------------------------------------------------
--Ubah isi STRING FILE_DEC dan FILE_ENC sesuai dengan lokasi file teks
--decrypt.txt dan encrypt.txt.
--------------------------------------------------------------------------------

	SIGNAL FILE_DEC								: STRING(1 TO 14) 				:= "D:\decrypt.txt";
	SIGNAL FILE_ENC								: STRING(1 TO 14)					:= "D:\encrypt.txt";
	
--------------------------------------------------------------------------------

	SIGNAL STATUS_ENC, STATUS_DEC				: STRING(1 TO 15)					:= "               ";
	SIGNAL PASS										: STRING(1 TO N);
	SIGNAL TEMP_A									: UNSIGNED(7 DOWNTO 0);
	SIGNAL TEMP_B, TEMP_C, TEMP_D, TEMP_E	: UNSIGNED((N*8)-1 DOWNTO 0);
	SIGNAL HEX										: STRING(1 TO N*2);

--------------------------------------------------------------------------------
--Fungsi yang digunakan untuk merubah sinyal STD_LOGIC_VECTOR atau UNSIGNED
--menjadi data heksadesimal dalam bentuk STRING.

--Sumber:
--https://github.com/texane/vhdl/blob/master/src/sim/ghdlex_mein/txt_util.vhdl
--(dengan perubahan)
--------------------------------------------------------------------------------

   -- converts a std_logic_vector into a hex string.
   function hstr(slv: std_logic_vector) return string is
      variable hexlen: integer;
      variable longslv : std_logic_vector(127 downto 0):=(others => '0');
      variable hex : string(1 to 32);
      variable fourbit : std_logic_vector(3 downto 0);
   begin
      hexlen:=(slv'left+1)/4;
      if (slv'left+1) mod 4/=0 then
         hexlen := hexlen + 1;
      end if;
      longslv(slv'left downto 0) := slv;
      for i in (hexlen-1) downto 0 loop
          fourbit:=longslv(((i*4)+3) downto (i*4));
          case fourbit is
               when "0000" => hex(hexlen-I):='0';
               when "0001" => hex(hexlen-I):='1';
               when "0010" => hex(hexlen-I):='2';
               when "0011" => hex(hexlen-I):='3';
               when "0100" => hex(hexlen-I):='4';
               when "0101" => hex(hexlen-I):='5';
               when "0110" => hex(hexlen-I):='6';
               when "0111" => hex(hexlen-I):='7';
               when "1000" => hex(hexlen-I):='8';
               when "1001" => hex(hexlen-I):='9';
               when "1010" => hex(hexlen-I):='A';
               when "1011" => hex(hexlen-I):='B';
               when "1100" => hex(hexlen-I):='C';
               when "1101" => hex(hexlen-I):='D';
               when "1110" => hex(hexlen-I):='E';
               when "1111" => hex(hexlen-I):='F';
               when "ZZZZ" => hex(hexlen-I):='z';
               when "UUUU" => hex(hexlen-I):='u';
               when "XXXX" => hex(hexlen-I):='x';
               when others => hex(hexlen-I):='?';
          end case;
      end loop;
      return hex(1 to hexlen);
   end function hstr;

   function hstr(slv: unsigned) return string is
   begin
      return hstr(std_logic_vector(slv));
   end function hstr;

--------------------------------------------------------------------------------

BEGIN
	ENCRYPT: PROCESS(CLOCK)
		VARIABLE I			: INTEGER			:= 0;
		VARIABLE ROW		: LINE;
		VARIABLE PASS_2	: STRING(1 TO N);
	BEGIN
		IF(RISING_EDGE(CLOCK)) THEN
			IF(START = '1' AND MODE = '0') THEN
				IF(I = 0) THEN
					STATUS_ENC <= "Encryption     ";
					FILE_OPEN(DEC, FILE_DEC, READ_MODE);
					FILE_OPEN(ENC, FILE_ENC, WRITE_MODE);
					IF(NOT ENDFILE(DEC)) THEN
						READLINE(DEC, ROW);
						READ(ROW, PASS_2);
						PASS <= PASS_2;
					END IF;
				END IF;
				IF(I >= 1 AND I <= N) THEN
					STATUS_ENC <= "Converting...  ";
					TEMP_A <= TO_UNSIGNED(CHARACTER'POS(PASS(I)), 8);
				END IF;
				IF(I >= 2 AND I <= N+1) THEN

--------------------------------------------------------------------------------
--Apabila panjang password yang ingin di-encrypt atau di-decrypt kurang dari 16
--karakter, maka hapus atau comment CASE selain dari CASE 2 sampai N+1 dan CASE
--OTHERS.
--
--Contoh:
--Apabila panjang password = 8 karakter, maka hapus CASE selain CASE 2-9 dan
--CASE OTHERS (CASE 10-17).
--------------------------------------------------------------------------------

				CASE I IS
						WHEN 2		=> TEMP_B((N*8)-1 DOWNTO (N*8)-8)			<= TEMP_A;
						WHEN 3		=> TEMP_B((N*8)-8-1 DOWNTO (N*8)-8*2)		<= TEMP_A;
						WHEN 4		=> TEMP_B((N*8)-8*2-1 DOWNTO (N*8)-8*3)	<= TEMP_A;
						WHEN 5		=> TEMP_B((N*8)-8*3-1 DOWNTO (N*8)-8*4)	<= TEMP_A;
						WHEN 6		=> TEMP_B((N*8)-8*4-1 DOWNTO (N*8)-8*5)	<= TEMP_A;
						WHEN 7		=> TEMP_B((N*8)-8*5-1 DOWNTO (N*8)-8*6)	<= TEMP_A;
						WHEN 8		=> TEMP_B((N*8)-8*6-1 DOWNTO (N*8)-8*7)	<= TEMP_A;
						WHEN 9		=> TEMP_B((N*8)-8*7-1 DOWNTO (N*8)-8*8)	<= TEMP_A;
						WHEN 10		=> TEMP_B((N*8)-8*8-1 DOWNTO (N*8)-8*9)	<= TEMP_A;
						WHEN 11		=> TEMP_B((N*8)-8*9-1 DOWNTO (N*8)-8*10)	<= TEMP_A;
						WHEN 12		=> TEMP_B((N*8)-8*10-1 DOWNTO (N*8)-8*11)	<= TEMP_A;
						WHEN 13		=> TEMP_B((N*8)-8*11-1 DOWNTO (N*8)-8*12)	<= TEMP_A;
						WHEN 14		=> TEMP_B((N*8)-8*12-1 DOWNTO (N*8)-8*13)	<= TEMP_A;
						WHEN 15		=> TEMP_B((N*8)-8*13-1 DOWNTO (N*8)-8*14)	<= TEMP_A;
						WHEN 16		=> TEMP_B((N*8)-8*14-1 DOWNTO (N*8)-8*15)	<= TEMP_A;
						WHEN 17		=> TEMP_B((N*8)-8*15-1 DOWNTO (N*8)-8*16)	<= TEMP_A;
						WHEN OTHERS	=> TEMP_A											<= TEMP_A;
					END CASE;

--------------------------------------------------------------------------------

				ELSIF(I = N+2) THEN
					STATUS_ENC <= "Encrypting...  ";
					CASE HASH(7) IS
						WHEN '0' 	=> TEMP_C <= ROTATE_LEFT(TEMP_B, TO_INTEGER(UNSIGNED(HASH(6 DOWNTO 0))));
						WHEN '1' 	=> TEMP_C <= ROTATE_RIGHT(TEMP_B, TO_INTEGER(UNSIGNED(HASH(6 DOWNTO 0))));
						WHEN OTHERS	=> TEMP_B <= TEMP_B;
					END CASE;
				ELSIF(I = N+3) THEN
					STATUS_ENC <= "Binary Copied  ";
					WRITE(ROW, TO_BITVECTOR(STD_LOGIC_VECTOR(TEMP_C)));
					WRITELINE(ENC, ROW);
				ELSIF(I = N+4) THEN
					HEX <= HSTR(TEMP_C);
				ELSIF(I = N+5) THEN
					STATUS_ENC <= "Hex Copied     ";
					WRITE(ROW, HEX);
					WRITELINE(ENC, ROW);
					FILE_CLOSE(DEC);
					FILE_CLOSE(ENC);
				END IF;
			END IF;
			IF(I <= N+5) THEN
				I := I + 1;
			END IF;
		END IF;
	END PROCESS;

--------------------------------------------------------------------------------
--------------------------------------------------------------------------------

	DECRYPT: PROCESS(CLOCK)
		VARIABLE I			: INTEGER								:= 0;
		VARIABLE ROW		: LINE;
		VARIABLE TEMP_2	: BIT_VECTOR((N*8)-1 DOWNTO 0);
	BEGIN
		IF(RISING_EDGE(CLOCK)) THEN
			IF(START = '1' AND MODE = '1') THEN
				IF(I = 0) THEN
					STATUS_DEC <= "Decryption     ";
					FILE_OPEN(ENC, FILE_ENC, READ_MODE);
					FILE_OPEN(DEC, FILE_DEC, WRITE_MODE);
					IF(NOT ENDFILE(ENC)) THEN
						READLINE(ENC, ROW);
						READ(ROW, TEMP_2);
						TEMP_D <= UNSIGNED(TO_STDLOGICVECTOR(TEMP_2));
					END IF;
				ELSIF(I = 1) THEN
					STATUS_DEC <= "Decrypting...  ";
					CASE HASH(7) IS
						WHEN '0' 	=> TEMP_E <= ROTATE_RIGHT(TEMP_D, TO_INTEGER(UNSIGNED(HASH(6 DOWNTO 0))));
						WHEN '1' 	=> TEMP_E <= ROTATE_LEFT(TEMP_D, TO_INTEGER(UNSIGNED(HASH(6 DOWNTO 0))));
						WHEN OTHERS	=> TEMP_D <= TEMP_D;
					END CASE;
				ELSIF(I >= 2 AND I <= N+1) THEN
					STATUS_DEC <= "Converting...  ";

--------------------------------------------------------------------------------
--Apabila panjang password yang ingin di-encrypt atau di-decrypt kurang dari 16
--karakter, maka hapus atau comment CASE selain dari CASE 2 sampai N+1 dan CASE
--OTHERS.
--
--Contoh:
--Apabila panjang password = 8 karakter, maka hapus CASE selain CASE 2-9 dan
--CASE OTHERS (CASE 10-17).
--------------------------------------------------------------------------------

				CASE I IS
						WHEN 2		=> WRITE(ROW, CHARACTER'VAL(TO_INTEGER(TEMP_E((N*8)-1 DOWNTO (N*8)-8))));
						WHEN 3		=> WRITE(ROW, CHARACTER'VAL(TO_INTEGER(TEMP_E((N*8)-8-1 DOWNTO (N*8)-8*2))));
						WHEN 4		=> WRITE(ROW, CHARACTER'VAL(TO_INTEGER(TEMP_E((N*8)-8*2-1 DOWNTO (N*8)-8*3))));
						WHEN 5		=> WRITE(ROW, CHARACTER'VAL(TO_INTEGER(TEMP_E((N*8)-8*3-1 DOWNTO (N*8)-8*4))));
						WHEN 6		=> WRITE(ROW, CHARACTER'VAL(TO_INTEGER(TEMP_E((N*8)-8*4-1 DOWNTO (N*8)-8*5))));
						WHEN 7		=> WRITE(ROW, CHARACTER'VAL(TO_INTEGER(TEMP_E((N*8)-8*5-1 DOWNTO (N*8)-8*6))));
						WHEN 8		=> WRITE(ROW, CHARACTER'VAL(TO_INTEGER(TEMP_E((N*8)-8*6-1 DOWNTO (N*8)-8*7))));
						WHEN 9		=> WRITE(ROW, CHARACTER'VAL(TO_INTEGER(TEMP_E((N*8)-8*7-1 DOWNTO (N*8)-8*8))));
						WHEN 10		=> WRITE(ROW, CHARACTER'VAL(TO_INTEGER(TEMP_E((N*8)-8*8-1 DOWNTO (N*8)-8*9))));
						WHEN 11		=> WRITE(ROW, CHARACTER'VAL(TO_INTEGER(TEMP_E((N*8)-8*9-1 DOWNTO (N*8)-8*10))));
						WHEN 12		=> WRITE(ROW, CHARACTER'VAL(TO_INTEGER(TEMP_E((N*8)-8*10-1 DOWNTO (N*8)-8*11))));
						WHEN 13		=> WRITE(ROW, CHARACTER'VAL(TO_INTEGER(TEMP_E((N*8)-8*11-1 DOWNTO (N*8)-8*12))));
						WHEN 14		=> WRITE(ROW, CHARACTER'VAL(TO_INTEGER(TEMP_E((N*8)-8*12-1 DOWNTO (N*8)-8*13))));
						WHEN 15		=> WRITE(ROW, CHARACTER'VAL(TO_INTEGER(TEMP_E((N*8)-8*13-1 DOWNTO (N*8)-8*14))));
						WHEN 16		=> WRITE(ROW, CHARACTER'VAL(TO_INTEGER(TEMP_E((N*8)-8*14-1 DOWNTO (N*8)-8*15))));
						WHEN 17		=> WRITE(ROW, CHARACTER'VAL(TO_INTEGER(TEMP_E((N*8)-8*15-1 DOWNTO (N*8)-8*16))));
						WHEN OTHERS	=> TEMP_E <= TEMP_E;
					END CASE;

--------------------------------------------------------------------------------

				ELSIF(I = N+2) THEN
					STATUS_DEC <= "Password Copied";
					WRITELINE(DEC, ROW);
					FILE_CLOSE(DEC);
					FILE_CLOSE(ENC);
				END IF;
			END IF;
			IF(I <= N+2) THEN
				I := I + 1;
			END IF;
		END IF;
	END PROCESS;
END ARCHITECTURE;
