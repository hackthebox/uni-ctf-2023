using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Nexus_Void.Helpers
{
    public class JWTHelper
    {
        private readonly IConfiguration _configuration;

        public JWTHelper(IConfiguration configuration) 
        {
            _configuration = configuration;
        }

        public string GenerateJwtToken(string username, string id) 
        {
            var secretKey = Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]);

            var claims = new Claim[] {
                new Claim("username", username),
                new Claim("ID", id)

            };

            var credentials = new SigningCredentials(new SymmetricSecurityKey(secretKey), SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(_configuration["JWT:Issuer"],
                _configuration["JWT:Issuer"],
                claims,
                expires: DateTime.Now.AddDays(7),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public string ValidateToken(string token)
        {
            var secretKey = Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]);
            var securityKey = new SymmetricSecurityKey(secretKey);

            var Issuer = _configuration["JWT:Issuer"];

            var tokenHandler = new JwtSecurityTokenHandler();

            try 
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = false,
                    ValidIssuer = Issuer,
                    IssuerSigningKey = securityKey
                }, out SecurityToken validatedToken);

                return validatedToken.ToString();
            }
            catch 
            {
                return false.ToString();
            }

        }

        public string getClaims(string token, string claimType)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            try
            {
                var securityToken = tokenHandler.ReadToken(token) as JwtSecurityToken;
                var stringClaimValue = securityToken.Claims.First(Claim => Claim.Type == claimType).Value;
                return stringClaimValue;
            }
            catch
            {
                return "";
            }

        }

    }
}

