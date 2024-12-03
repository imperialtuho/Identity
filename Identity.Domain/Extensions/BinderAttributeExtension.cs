using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Identity.Domain.Extensions
{
    // Attribute for binding CSV values to IList<string>
    [AttributeUsage(AttributeTargets.Parameter, AllowMultiple = false)]
    public class CsvBinderAttribute : ModelBinderAttribute
    {
        public CsvBinderAttribute() : base(typeof(CsvModelBinder))
        {
        }
    }

    // Model Binder for CSV binding
    public class CsvModelBinder : IModelBinder
    {
        public Task BindModelAsync(ModelBindingContext bindingContext)
        {
            ValueProviderResult valueProviderResult = bindingContext.ValueProvider.GetValue(bindingContext.ModelName);

            if (valueProviderResult == ValueProviderResult.None)
            {
                return Task.CompletedTask;
            }

            bindingContext.ModelState.SetModelValue(bindingContext.ModelName, valueProviderResult);

            string? value = valueProviderResult.FirstValue;

            if (string.IsNullOrWhiteSpace(value))
            {
                return Task.CompletedTask;
            }

            // Split the CSV values into a list
            string[]? values = value.Split(',', StringSplitOptions.RemoveEmptyEntries);

            // Set the model binding result
            bindingContext.Result = ModelBindingResult.Success(values.ToList());

            return Task.CompletedTask;
        }
    }
}