using System.ComponentModel.DataAnnotations;

namespace Identity.Application.Dtos.Users
{
    public class LoginDto
    {
        [Required]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }
    }
}