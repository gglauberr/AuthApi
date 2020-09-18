using Auth.Domain.Model;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Text;

namespace Auth.Data
{
    public class AuthContext : IdentityDbContext<User>
    {
        public AuthContext(DbContextOptions<AuthContext> options) : base(options)
        {

        }

        public DbSet<Cliente> Cliente { get; set; }
    }
}
