using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace Auth.Domain.Model
{
    public class ValidationCustom<TUser> : IPasswordValidator<TUser> where TUser : class
    {
        public async Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string password)
        {
            var username = await manager.GetUserNameAsync(user);

            if (username == password)
                return IdentityResult.Failed(
                    new IdentityError { Description = "A senha não pode ser igual ao username" }
                );
            if (password.Contains("password"))
                return IdentityResult.Failed(
                    new IdentityError { Description = "A senha não pode ser password" }
                );

            return IdentityResult.Success;
        }
    }
}
