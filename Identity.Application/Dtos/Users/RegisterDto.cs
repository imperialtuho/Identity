using System.ComponentModel.DataAnnotations;

namespace Identity.Application.Dtos.Users
{
    public class RegisterDto
    {
        [Required]
        public required string UserName { get; set; }

        [Required]
        public required string Password { get; set; }

        [Required]
        public required string Email { get; set; }

        public bool IsManager { get; set; }

        public IList<string>? Roles { get; set; }

        public IList<ClaimDto>? Claims { get; set; }
    }
}