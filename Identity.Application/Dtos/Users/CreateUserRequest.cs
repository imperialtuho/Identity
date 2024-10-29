using System.ComponentModel.DataAnnotations;

namespace Identity.Application.Dtos.Users
{
    public class CreateUserRequest
    {
        [Required]
        public required string UserName { get; set; }

        [EmailAddress]
        public required string Email { get; set; }

        [Required]
        public required string Password { get; set; }

        [Required]
        public required string FirstName { get; set; }

        [Required]
        public required string LastName { get; set; }

        [Required]
        [StringLength(50)]
        public required string DisplayName { get; set; }

        [StringLength(500)]
        public string? Bio { get; set; }

        [Url]
        public string? ProfilePictureUrl { get; set; }
    }
}