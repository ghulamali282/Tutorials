using Google.Apis.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System;
using System.Threading.Tasks;
using Tutorials.Dto;
using Tutorials.Helpers;

namespace Tutorials.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly UserManager<IdentityUser> _userManager;

        public AuthController(IConfiguration configuration, UserManager<IdentityUser> userManager)
        {
            _configuration = configuration;
            _userManager = userManager;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login(ExternalAuthDto externalAuth)
        {
            var clientId = _configuration["GoogleAuthSettings:ClientId"];
           
            GoogleJsonWebSignature.Payload payload; 
           
            try
            {
                payload = await JwtHandler.VerifyGoogleToken(externalAuth, clientId);
            }
            catch (InvalidJwtException)
            {
                return Unauthorized("Invalid login request.");
            }
            catch (Exception)
            {
                return BadRequest("Invalid login request.");
            }

            var info = new UserLoginInfo(externalAuth.Provider, payload.Subject, externalAuth.Provider);
            var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);

            if (user == null)
            {
                user = await _userManager.FindByEmailAsync(payload.Email);
                if (user == null)
                {
                    user = new IdentityUser { Email = payload.Email, UserName = payload.Email };
                    await _userManager.CreateAsync(user);
                    await _userManager.AddLoginAsync(user, info);
                }
                else
                {
                    await _userManager.AddLoginAsync(user, info);
                }
            }
            if (user == null)
            {
                return BadRequest("Invalid login request.");
            }

            var jwtSecret = _configuration["JwtConfig:Secret"];

            var token = JwtHandler.GenerateToken(user,jwtSecret);

            return Ok(new LoginResponseDto { Token = token, IsAuthSuccessfull = true });
        }
    }
}
