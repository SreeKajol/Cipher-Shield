#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#ifdef _WIN32
#include <windows.h>
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

void enable_ansi_escape_codes()
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;

    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) return;

    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}
#endif

#define RESET "\033[0m"
#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN "\033[36m"
#define BOLD "\033[1m"

// --- Playfair Cipher Implementation ---
char playfair_matrix[5][5];
void generate_playfair_matrix(const char *key)
{
    int used[26] = {0};
    used['J' - 'A'] = 1; // Treat 'J' as 'I'
    int row = 0, col = 0;

    for (int i = 0; key[i] != '\0'; i++)
    {
        char c = toupper(key[i]);
        if (c == 'J') c = 'I'; // Treat J as I
        if (!used[c - 'A'])
        {
            playfair_matrix[row][col++] = c;
            used[c - 'A'] = 1;
            if (col == 5)
            {
                col = 0;
                row++;
            }
        }
    }

    for (char c = 'A'; c <= 'Z'; c++)
    {
        if (!used[c - 'A'])
        {
            playfair_matrix[row][col++] = c;
            if (col == 5)
            {
                col = 0;
                row++;
            }
        }
    }
}

void find_position(char c, int *row, int *col)
{
    if (c == 'J') c = 'I'; // Treat J as I
    for (int r = 0; r < 5; r++)
    {
        for (int c2 = 0; c2 < 5; c2++)
        {
            if (playfair_matrix[r][c2] == c)
            {
                *row = r;
                *col = c2;
                return;
            }
        }
    }
}

void playfair_encrypt_decrypt(const char *input, char *output, const char *key, int mode)
{
    generate_playfair_matrix(key);

    int length = strlen(input);
    char processed_input[1024];
    int processed_length = 0;

    // Process input: Remove spaces and replace J with I
    for (int i = 0; i < length; i++)
    {
        char c = toupper(input[i]);
        if (isalpha(c))
        {
            if (c == 'J') c = 'I';
            processed_input[processed_length++] = c;
        }
    }

    // Add padding if needed
    for (int i = 0; i < processed_length; i += 2)
    {
        if (i + 1 == processed_length || processed_input[i] == processed_input[i + 1])
        {
            for (int j = processed_length; j > i + 1; j--)
            {
                processed_input[j] = processed_input[j - 1];
            }
            processed_input[i + 1] = 'X';
            processed_length++;
        }
    }

    processed_input[processed_length] = '\0';

    for (int i = 0; i < processed_length; i += 2)
    {
        int row1, col1, row2, col2;
        find_position(processed_input[i], &row1, &col1);
        find_position(processed_input[i + 1], &row2, &col2);

        if (row1 == row2)   // Same row
        {
            col1 = (col1 + mode) % 5;
            col2 = (col2 + mode) % 5;
        }
        else if (col1 == col2)     // Same column
        {
            row1 = (row1 + mode) % 5;
            row2 = (row2 + mode) % 5;
        }
        else     // Rectangle swap
        {
            int temp = col1;
            col1 = col2;
            col2 = temp;
        }

        output[i] = playfair_matrix[row1][col1];
        output[i + 1] = playfair_matrix[row2][col2];
    }
    output[processed_length] = '\0';
}

// XOR Encryption
char xor_encrypt(char c, char key)
{
    return c ^ key;
}

// Caesar Cipher
char caesar_encrypt(char c, int shift)
{
    if ('A' <= c && c <= 'Z')
        return ((c - 'A' + shift + 26) % 26) + 'A';
    if ('a' <= c && c <= 'z')
        return ((c - 'a' + shift + 26) % 26) + 'a';
    return c;
}

// Substitution Cipher
char substitution_encrypt(char c, const char *sub_table, int reverse)
{
    if (reverse)   // For decryption, reverse the substitution table
    {
        for (int i = 0; i < 26; i++)
        {
            if (sub_table[i] == c || sub_table[i] + ('a' - 'A') == c)
                return ('A' <= c && c <= 'Z') ? i + 'A' : i + 'a';
        }
    }
    else
    {
        if ('A' <= c && c <= 'Z')
            return sub_table[c - 'A'];
        if ('a' <= c && c <= 'z')
            return sub_table[c - 'a'] + ('a' - 'A');
    }
    return c;
}

// --- RSA Encryption/Decryption ---
long long mod_exp(long long base, long long exp, long long mod)
{
    long long result = 1;
    base = base % mod;
    while (exp > 0)
    {
        if (exp % 2 == 1)
            result = (result * base) % mod;
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

void rsa_keygen(long long *e, long long *d, long long *n)
{
    long long p = 199, q = 211; // Small primes for simplicity
    *n = p * q;
    long long phi = (p - 1) * (q - 1);

    *e = 65537; // Commonly used value
    long long k = 1;
    while ((1 + k * phi) % *e != 0)
        k++;
    *d = (1 + k * phi) / *e;
}

char rsa_encrypt(char c, long long e, long long n)
{
    return (char)mod_exp(c, e, n);
}

char rsa_decrypt(char c, long long d, long long n)
{
    return (char)mod_exp(c, d, n);
}

// --- DES Encryption/Decryption ---
void des_encrypt_decrypt(char *block, char key, int mode)
{
    for (int i = 0; i < 8; i++)
    {
        block[i] = mode == 1 ? block[i] ^ key : block[i] ^ key; // XOR-based simplification
    }
}


void display_file(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        printf(RED "Error opening file.\n" RESET);
        return;
    }

    char c;
    printf(YELLOW "File Content of '%s':\n" RESET, filename);
    while ((c = fgetc(file)) != EOF)
    {
        putchar(c);
    }
    printf("\n");
    fclose(file);
}

void displayLoginScreen()
{
    printf(CYAN "=========================================\n" RESET);
    printf(BOLD MAGENTA "      WELCOME TO FILE ENCRYPTOR SYSTEM    \n" RESET);
    printf(CYAN "=========================================\n" RESET);
    printf(BOLD YELLOW "             Enter Credentials            \n" RESET);
    printf(CYAN "-----------------------------------------\n" RESET);
}

int login()
{
    char input_username[100], input_password[100];
    char stored_username[] = "admin";
    char stored_password[] = "password";
    int attempts = 0;

    while (attempts < 3)
    {
        displayLoginScreen();

        printf(BLUE "Username: " RESET);
        scanf("%s", input_username);
        printf(BLUE "Password: " RESET);
        scanf("%s", input_password);

        if (strcmp(input_username, stored_username) == 0 &&
                strcmp(input_password, stored_password) == 0)
        {
            printf(GREEN "\nLogin successful!\n" RESET);
            return 1;
        }
        else
        {
            printf(RED "\nInvalid credentials. Try again.\n" RESET);
            attempts++;
        }
    }

    printf(RED "\nToo many failed attempts. Exiting...\n" RESET);
    return 0;
}

void process_file(const char *input_filename, const char *output_filename,
                  const char *password, int algorithm, int mode) {
    FILE *input = fopen(input_filename, "r");
    FILE *output = fopen(output_filename, "w");

    if (input == NULL || output == NULL) {
        printf(RED "Error opening file.\n" RESET);
        return;
    }

    if (password == NULL || strlen(password) == 0) {
        printf(RED "Error: Password cannot be empty.\n" RESET);
        fclose(input);
        fclose(output);
        return;
    }

    char key = password[0];
    int shift = (key % 26); // Password determines shift
    const char substitution_table[26] = "QWERTYUIOPASDFGHJKLZXCVBNM"; // Example substitution table
    long long rsa_e, rsa_d, rsa_n;
    rsa_keygen(&rsa_e, &rsa_d, &rsa_n); // Generate RSA keys

    char c;
    char block[8];

    while ((c = fgetc(input)) != EOF) {
        char result = c;

        if (algorithm == 1) { // XOR
            result = xor_encrypt(c, key);
        } else if (algorithm == 2) { // Caesar
            result = caesar_encrypt(c, mode == 1 ? shift : -shift);
        } else if (algorithm == 3) { // Substitution
            result = substitution_encrypt(c, substitution_table, mode == 2);
        } else if (algorithm == 4) { // RSA
            result = mode == 1 ? rsa_encrypt(c, rsa_e, rsa_n)
                               : rsa_decrypt(c, rsa_d, rsa_n);
        } else if (algorithm == 5) { // DES
            int block_size = 8;
            int bytes_read = 0;

            while ((bytes_read = fread(block, 1, block_size, input)) > 0) {
                des_encrypt_decrypt(block, key, mode);
                fwrite(block, 1, bytes_read, output); // Write processed block
            }
            fclose(input);
            fclose(output);
            printf(GREEN "Operation completed successfully.\n" RESET);
            return;
        } else if (algorithm == 6) { // Playfair Cipher
            char input_text[1024];
            char processed_text[1024];
            int index = 0;

            do {
                input_text[index++] = c;
            } while ((c = fgetc(input)) != EOF);
            input_text[index] = '\0';

            playfair_encrypt_decrypt(input_text, processed_text, password, mode == 1 ? 1 : -1);
            fprintf(output, "%s", processed_text);

            fclose(input);
            fclose(output);
            printf(GREEN "Operation completed successfully.\n" RESET);
            return;
        }

        if (algorithm != 5 && algorithm != 6) {
            fputc(result, output);
        }
    }

    fclose(input);
    fclose(output);
    printf(GREEN "Operation completed successfully.\n" RESET);
}



// --- Add Playfair Cipher to Menu ---
int main()
{
#ifdef _WIN32
    enable_ansi_escape_codes();
#endif
    if (!login())
    {
        return 0;
    }

    int choice, algorithm;
    char input_filename[100], output_filename[100], password[100];

    do
    {
        printf(BOLD "\nChoose an option:\n" RESET);
        printf(BLUE "1. Encrypt a file\n" RESET);
        printf(BLUE "2. Decrypt a file\n" RESET);
        printf(BLUE "3. View a file's content\n" RESET);
        printf(BLUE "4. Exit\n" RESET);
        scanf("%d", &choice);

        switch (choice)
        {
        case 1:
        case 2:
            printf("Choose encryption algorithm:\n");
            printf("1. XOR Encryption\n");
            printf("2. Caesar Cipher\n");
            printf("3. Substitution Cipher\n");
            printf("4. RSA Encryption\n");
            printf("5. DES Encryption\n");
            printf("6. Playfair Cipher\n");
            scanf("%d", &algorithm);

            printf("Enter input file name: ");
            scanf("%s", input_filename);
            printf("Enter output file name: ");
            scanf("%s", output_filename);
            printf("Enter password: ");
            scanf("%s", password);

            process_file(input_filename, output_filename, password, algorithm, choice);
            break;

        case 3:
            printf("Enter file name to view: ");
            scanf("%s", input_filename);
            display_file(input_filename);
            break;

        case 4:
            printf(GREEN "Exiting...\n" RESET);
            break;

        default:
            printf(RED "Invalid choice! Please try again.\n" RESET);
        }
    }
    while (choice != 4);

    return 0;
}
