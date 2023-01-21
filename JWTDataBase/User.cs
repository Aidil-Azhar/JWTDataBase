namespace JWTDataBase
{
    public class User
    {
        public string UserName { get; set; } = string.Empty;
        public byte[] PasswordHas { get; set; }
        public byte[] PasswordSalt { get; set; }

    }
}
