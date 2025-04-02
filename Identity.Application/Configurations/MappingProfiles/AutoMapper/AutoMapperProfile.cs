using AutoMapper;
using Identity.Application.Dtos;
using Identity.Application.Dtos.Users;
using Identity.Domain.Entities;

namespace Identity.Application.Configurations.MappingProfiles.AutoMapper
{
    /// <summary>
    /// Configures the mappings for AutoMapper, defining how domain entities map to DTOs and vice versa.
    /// </summary>
    /// <remarks>
    /// This class inherits from <see cref="Profile"/> and defines the mapping configurations between domain
    /// entities and their corresponding data transfer objects (DTOs). The mappings can be used by AutoMapper to
    /// automatically convert between the two types. Additionally, the mappings can be customized as needed, including
    /// using specific member mappings, value conversions, or reverse mappings.
    /// </remarks>
    public class AutoMapperProfile : Profile
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AutoMapperProfile"/> class and defines mapping configurations.
        /// </summary>
        public AutoMapperProfile()
        {
            CreateMap<UserDto, User>().ReverseMap();
            CreateMap<Menu, MenuDto>().ReverseMap();
            CreateMap<RegisterDto, UserDto>().ReverseMap();
        }
    }
}