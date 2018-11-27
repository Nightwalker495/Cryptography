#include <list>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <functional>
#include <forward_list>

#include <openssl/md5.h>

typedef unsigned char byte_t;

class Md5Hash
{
public:
    static Md5Hash BuildFromHexHash(const std::string& md5_hex_hash)
    {
        byte_t bytes[MD5_DIGEST_LENGTH];

        for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
            auto curr_hex_str(md5_hex_hash.substr(i * 2, 2));
            auto curr_byte_val(
                    static_cast<byte_t>(std::stoi(curr_hex_str, nullptr, 16)));
            bytes[i] = curr_byte_val;
        }

        return Md5Hash(bytes);
    }

    static Md5Hash BuildFromPasswdAndSalt(const std::string& passwd,
            const std::string& salt)
    {
        byte_t digest[MD5_DIGEST_LENGTH];

        MD5_CTX ctx;
        MD5_Init(&ctx);
        MD5_Update(&ctx, passwd.c_str(), passwd.length());
        MD5_Update(&ctx, salt.c_str(), salt.length());
        MD5_Final(digest, &ctx);

        return Md5Hash(digest);
    }

    bool operator==(const Md5Hash& other) const
    {
        for (int i = 0; i < static_cast<int>(bytes_.size()); ++i) {
            if (bytes_[i] != other.bytes_[i])
                return false;
        }

        return true;
    }

    friend std::ostream& operator<<(std::ostream& stream, const Md5Hash& md5_hash)
    {
        std::string str;

        for (const auto& byte : md5_hash.bytes_) {
            char byte_hex[3];
            std::sprintf(byte_hex, "%02x", byte);
            str += byte_hex;
        }

        stream << str;

        return stream;
    }

private:
    Md5Hash(const byte_t bytes[MD5_DIGEST_LENGTH])
    {
        for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
            bytes_.emplace_back(bytes[i]);
    }

    std::vector<byte_t> bytes_;
};

class LoginInstance
{
public:
    LoginInstance(const std::string& login, const std::string& salt,
            const std::string& md5_hex_hash) :
            login_(login), salt_(salt), passwd_hash_(
                    Md5Hash::BuildFromHexHash(md5_hex_hash))
    {
    }

    bool IsPasswdCorrect(const std::string& passwd) const
    {
        return passwd_hash_ == Md5Hash::BuildFromPasswdAndSalt(passwd, salt_);
    }

    friend std::ostream& operator<<(std::ostream& stream,
            const LoginInstance& login_inst)
    {
        stream << login_inst.login_
                << " [" << login_inst.passwd_hash_
                << " | " << login_inst.salt_ << ']';

        return stream;
    }

private:
    std::string login_;
    std::string salt_;
    Md5Hash passwd_hash_;
};

class PasswordGeneratorInterface
{
public:
    virtual ~PasswordGeneratorInterface()
    {
    }

    virtual bool ForEach(
            const std::function<bool(const std::string&)>& passwd_check_func) = 0;
};

class WordlistPasswordGenerator : public PasswordGeneratorInterface
{
public:
    WordlistPasswordGenerator(const std::string& wordlist_file_path)
    {
        std::ifstream in_file;
        in_file.open(wordlist_file_path);

        std::string password;
        while (in_file >> password)
            passwords_.emplace_front(password);

        in_file.close();
    }

    virtual bool ForEach(
            const std::function<bool(const std::string&)>& passwd_check_func)
    {
        for (const auto& password : passwords_) {
            if (!passwd_check_func(password))
                return true;
        }

        return false;
    }

private:
    std::forward_list<std::string> passwords_;
};

class CharPasswordGenerator : public PasswordGeneratorInterface
{
public:
    CharPasswordGenerator(int passwd_len, bool use_alpha_lower,
            bool use_alpha_upper, bool use_digits) :
                passwd_len_(passwd_len)
    {
        InitAllowedChars(use_alpha_lower, use_alpha_upper, use_digits);
    }

    virtual bool ForEach(
                const std::function<bool(const std::string&)>& passwd_check_func)
    {
        passwd_check_func_ = passwd_check_func;
        std::string passwd(passwd_len_, '\0');
        return GeneratePasswds(0, &passwd);
    }

private:
    void InitAllowedChars(bool use_alpha_lower,
            bool use_alpha_upper, bool use_digits)
    {
        if (use_alpha_lower)
            AddCharsToAllowed('a', 'z');
        if (use_alpha_upper)
            AddCharsToAllowed('A', 'Z');
        if (use_digits)
            AddCharsToAllowed('0', '9');
    }

    void AddCharsToAllowed(char min_char, char max_char)
    {
        for (char c = min_char; c <= max_char; ++c)
            allowed_chars_.emplace_back(c);
    }

    bool GeneratePasswds(int pos, std::string* passwd)
    {
        if (pos >= passwd_len_)
            return !passwd_check_func_(*passwd);

        for (const auto c : allowed_chars_) {
            (*passwd)[pos] = c;

            if (GeneratePasswds(pos + 1, passwd))
                return true;
        }

        return false;
    }

    std::function<bool(const std::string&)> passwd_check_func_;
    int passwd_len_;
    std::list<char> allowed_chars_;
};

class BruteForceEngine
{
public:
    ~BruteForceEngine()
    {
        for (auto& passwd_generator : passwd_generators_)
            delete passwd_generator;
    }

    void AddWordlistPasswdGenerator(const std::string& wordlist_file_path)
    {
        passwd_generators_.push_back(
                new WordlistPasswordGenerator(wordlist_file_path));
    }

    void AddCharPasswdGenerator(int passwd_len, bool use_alpha_lower=false,
            bool use_alpha_upper=false, bool use_digits=false)
    {
        passwd_generators_.push_back(
                new CharPasswordGenerator(passwd_len,
                        use_alpha_lower, use_alpha_upper, use_digits));
    }

    bool BruteForcePasswd(const LoginInstance& login_inst,
            std::string* plain_passwd) const
    {
        auto passwd_check_func = [&login_inst, &plain_passwd]
                                  (const std::string& passwd) {
            if (login_inst.IsPasswdCorrect(passwd)) {
                *plain_passwd = passwd;
                return false;
            }

            return true;
        };

        for (const auto& passwd_gen : passwd_generators_) {
            if (passwd_gen->ForEach(passwd_check_func))
                return true;
        }

        return false;
    }

private:
    std::list<PasswordGeneratorInterface*> passwd_generators_;
};

static LoginInstance* ParseInputAsLoginInstance(
        const std::string& input)
{
    if (input.empty())
        return nullptr;

    std::stringstream ss(input);
    std::vector<std::string> tokens;
    std::string token;

    while (std::getline(ss, token, ':'))
        tokens.emplace_back(token);

    return new LoginInstance(tokens[0], tokens[1], tokens[2]);
}

static void InitPasswdGenerators(BruteForceEngine* brute_force_engine)
{
    brute_force_engine->AddWordlistPasswdGenerator("sk_names_wordlist.txt");
    brute_force_engine->AddCharPasswdGenerator(4, true, true, true);
    brute_force_engine->AddCharPasswdGenerator(6, true);
}

int main()
{
    std::ios_base::sync_with_stdio(false);

    BruteForceEngine brute_force_engine;
    InitPasswdGenerators(&brute_force_engine);

    std::string login_info_input;
    while (std::getline(std::cin, login_info_input)) {
        auto login_inst = ParseInputAsLoginInstance(login_info_input);
        if (login_inst == nullptr)
            continue;

        std::cout << *login_inst << " --> ";
        std::string plain_passwd;
        if (brute_force_engine.BruteForcePasswd(*login_inst, &plain_passwd))
            std::cout << "password FOUND: " << plain_passwd;
        else
            std::cout << "password not found";
        std::cout << std::endl;

        delete login_inst;
    }

    return 0;
}
