using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Auth.Api.DTO
{
    public class TwoFactor
    {
        [Required]
        public string Token { get; set; }
    }
}
