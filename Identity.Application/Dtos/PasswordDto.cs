using System.ComponentModel.DataAnnotations;

namespace Identity.Application.Dtos
{
    public class PasswordDto
    {
        [Required]
        public string Password { get; set; }
    }
}