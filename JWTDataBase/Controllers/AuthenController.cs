using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JWTDataBase.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;

        public AuthenController(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDTO request)
        {
            CreatPasswordHas(request.Password, out byte[] passwordHas, out byte[] passwordSalt);
            
            user.UserName = request.UserName;   
            user.PasswordHas = passwordHas; 
            user.PasswordSalt = passwordSalt;
            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<User>> Login(UserDTO request)
        {
            if (user.UserName != request.UserName)
            {
                return BadRequest("User tidak ditemukan");
            }
            if(VerifyPasswordHas(request.Password, user.PasswordHas, user.PasswordSalt))
            {
                return BadRequest("Password anda Salah.");
            }
            string token = CreateToken(user);
            return Ok(token);
        }
        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName)
            };
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value));
            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred);
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
           
        }
        private void CreatPasswordHas(string password, out byte[] passwordhas, out byte[] passwordSalt)
        {
             using(var hmac = new HMACSHA512())
            {
                passwordSalt =hmac.Key; 
                passwordhas = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }
        private bool VerifyPasswordHas(string password, byte[] passwordhas, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computeHas = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computeHas.SequenceEqual(passwordhas); 
            }
        }
    }
}
