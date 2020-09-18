using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Auth.Api.DTO;
using Auth.Domain.Model;
using AutoMapper;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Api.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    [AllowAnonymous]
    public class UserController : ControllerBase
    {
        private readonly IMapper mapper;
        private readonly UserManager<User> userManager;
        private readonly SignInManager<User> signInManager;
        private readonly IConfiguration configuration;
        private readonly IUserClaimsPrincipalFactory<User> userClaimsPrincipalFactory;
        public UserController(
              IMapper mapper
            , UserManager<User> userManager
            , SignInManager<User> signInManager
            , IConfiguration configuration
            , IUserClaimsPrincipalFactory<User> userClaimsPrincipalFactory
        )
        {
            this.mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
            this.userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            this.signInManager = signInManager ?? throw new ArgumentNullException(nameof(signInManager));
            this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            this.userClaimsPrincipalFactory = userClaimsPrincipalFactory ?? throw new ArgumentNullException(nameof(userClaimsPrincipalFactory));
        }

        [HttpPost]
        public async Task<IActionResult> Login(UserLoginDTO userLogin)
        {
            try
            {
                var user = await userManager.FindByNameAsync(userLogin.UserName);

                if (user != null && !await userManager.IsLockedOutAsync(user))
                {
                    if (await userManager.CheckPasswordAsync(user, userLogin.Password))
                    {
                        var appUser = await userManager.Users
                                .FirstOrDefaultAsync((u) => u.NormalizedUserName.Equals(user.UserName.ToUpper()));

                        var userToReturn = mapper.Map<UserDTO>(appUser);

                        if (!await userManager.IsEmailConfirmedAsync(user))
                        {
                            throw new Exception("E-mail não está Válido!");
                        }

                        await userManager.ResetAccessFailedCountAsync(user);

                        if (await userManager.GetTwoFactorEnabledAsync(user))
                        {
                            var validator = await userManager.GetValidTwoFactorProvidersAsync(user);

                            if (validator.Contains("Email"))
                            {
                                var token = await userManager.GenerateTwoFactorTokenAsync(user, "Email");

                                System.IO.File.WriteAllText("email2sv.txt", token);

                                await HttpContext.SignInAsync(IdentityConstants.TwoFactorUserIdScheme,
                                    Store2FA(user.Id, "Email"));
                            }
                        }

                        var principal = await userClaimsPrincipalFactory.CreateAsync(user);

                        await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, principal);

                        return Ok(new
                        {
                            Token = await GerateToken(appUser),
                            User = userToReturn
                        });
                    }

                    var result = await signInManager.CheckPasswordSignInAsync(user, userLogin.Password, true);

                    if (result.Succeeded)
                    {
                        var appUser = await userManager.Users
                                .FirstOrDefaultAsync((u) => u.NormalizedUserName.Equals(user.UserName.ToUpper()));

                        var userToReturn = mapper.Map<UserDTO>(appUser);

                        return Ok(new
                        {
                            Token = await GerateToken(appUser),
                            User = userToReturn
                        });
                    }
                }
          
                return Unauthorized();
            }
            catch(Exception ex)
            {
                return this.StatusCode(StatusCodes.Status500InternalServerError,
                    $"ERROR {ex.Message}");
            }
        }

        [HttpPost]
        public async Task<IActionResult> Register(UserDTO userDTO)
        {
            try
            {
                var user = await userManager.FindByNameAsync(userDTO.UserName);

                if(user == null)
                {
                    user = new User()
                    {
                        UserName = userDTO.UserName,
                        Email = userDTO.UserName
                    };

                    var result = await userManager.CreateAsync(user, userDTO.Password);

                    if(result.Succeeded)
                    {
                        var appUser = await userManager.Users
                                .FirstOrDefaultAsync((u) => u.NormalizedUserName.Equals(userDTO.UserName.ToUpper()));

                        var token = await GerateToken(appUser);

                        var confirmationEmail = Url.Action("ConfirmEmailAddress", "User",
                            new { token = token, email = user.Email }, Request.Scheme);

                        System.IO.File.WriteAllText("confirmationEmail.txt", confirmationEmail);

                        return Ok(token);
                    }
                }

                return Unauthorized();
            }
            catch (Exception ex)
            {
                return this.StatusCode(StatusCodes.Status500InternalServerError,
                    $"ERROR {ex.Message}");
            }
        }

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPassword model)
        {
            try
            {
                var user = await userManager.FindByEmailAsync(model.Email);

                if (user == null) throw new Exception("Usuário não encontrado");

                var token = await userManager.GeneratePasswordResetTokenAsync(user);
                var resetURL = Url.Action("ResetPassword", "Home",
                    new { token = token, email = model.Email }, Request.Scheme);

                System.IO.File.WriteAllText("resetLink.txt", resetURL);

                return Ok();
            }
            catch(Exception ex)
            {
                return this.StatusCode(StatusCodes.Status500InternalServerError,
                    $"ERROR {ex.Message}");
            }
        }

        [HttpPost]
        public async Task<IActionResult> TwoFactor(TwoFactor model)
        {
            try
            {
                var result = await HttpContext.AuthenticateAsync(IdentityConstants.TwoFactorUserIdScheme);
                if (!result.Succeeded)
                {
                    throw new Exception("Seu token expirou!");
                }

                var user = await userManager.FindByIdAsync(result.Principal.FindFirstValue("sub"));

                if (user == null) throw new Exception("Usuário não encontrado!");

                var isValid = await userManager.VerifyTwoFactorTokenAsync(
                        user,
                        result.Principal.FindFirstValue("amr"), model.Token);

                if (isValid)
                {
                    await HttpContext.SignOutAsync(IdentityConstants.TwoFactorUserIdScheme);

                    var claimsPrincipal = await userClaimsPrincipalFactory.CreateAsync(user);
                    await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, claimsPrincipal);

                    return Ok();
                }
                else
                {
                    throw new Exception("Invalid Token");
                }
            }
            catch(Exception ex)
            {
                return this.StatusCode(StatusCodes.Status500InternalServerError,
                    $"ERROR {ex.Message}");
            }
        }

        [HttpGet("{token}/{email}")]
        public async Task<IActionResult> ConfirmEmailAddress(string token, string email)
        {
            try
            {
                var user = await userManager.FindByEmailAsync(email);

                if (user == null) throw new Exception("Usuário não encontrado!");

                var result = await userManager.ConfirmEmailAsync(user, token);

                if (result.Succeeded)
                {
                    return Ok("Success");
                }
                else
                {
                    throw new Exception("Error");
                }
            }
            catch(Exception ex)
            {
                return this.StatusCode(StatusCodes.Status500InternalServerError,
                    $"ERROR {ex.Message}");
            }
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPassword model)
        {
            try
            {
                var user = await userManager.FindByEmailAsync(model.Email);

                if (user == null) throw new Exception("Usuário não encontrado!");

                var result = await userManager.ResetPasswordAsync(user,
                        model.Token, model.Password);

                if (!result.Succeeded)
                {
                    throw new Exception("Error");
                }

                return Ok("Success");
            }
            catch(Exception ex)
            {
                return this.StatusCode(StatusCodes.Status500InternalServerError,
                    $"ERROR {ex.Message}");
            }
        }

        public ClaimsPrincipal Store2FA(string userId, string provider)
        {
            var identity = new ClaimsIdentity(new List<Claim>
            {
                new Claim("sub", userId),
                new Claim("amr", provider)
            }, IdentityConstants.TwoFactorUserIdScheme);

            return new ClaimsPrincipal(identity);
        }

        public async Task<string> GerateToken(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.UserName)
            };

            //var roles = await userManager.GetRolesAsync(user);

            //foreach (var role in roles)
            //{
            //    claims.Add(new Claim(ClaimTypes.Role, role));
            //}

            var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(
                configuration.GetSection("AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var tokenDescription = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = creds
            };

            var tokenHandler = new JwtSecurityTokenHandler();

            var token = tokenHandler.CreateToken(tokenDescription);

            return tokenHandler.WriteToken(token);
        }
    }
}
