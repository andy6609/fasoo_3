#include "windows_ocr.h"

#include <cstdlib>
#include <cstring>
#include <string>

#include <roapi.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Data.Pdf.h>
#include <winrt/Windows.Graphics.Imaging.h>
#include <winrt/Windows.Media.Ocr.h>
#include <winrt/Windows.Storage.Streams.h>

#pragma comment(lib, "runtimeobject.lib")
#pragma comment(lib, "windowsapp.lib")

namespace {

void set_status(char* status, size_t status_size, const char* value)
{
    if (status == nullptr || status_size == 0) return;
    if (value == nullptr) value = "";
    strncpy_s(status, status_size, value, _TRUNCATE);
}

int copy_result(const std::string& text, char** output, size_t* output_length)
{
    char* copy = static_cast<char*>(std::malloc(text.size() + 1));
    if (copy == nullptr) return -1;
    if (!text.empty()) std::memcpy(copy, text.data(), text.size());
    copy[text.size()] = '\0';
    *output = copy;
    *output_length = text.size();
    return 1;
}

winrt::Windows::Storage::Streams::InMemoryRandomAccessStream make_stream(
    const unsigned char* data,
    size_t length)
{
    using namespace winrt::Windows::Storage::Streams;
    InMemoryRandomAccessStream stream;
    DataWriter writer(stream.GetOutputStreamAt(0));
    writer.WriteBytes(winrt::array_view<const uint8_t>(data, data + length));
    writer.StoreAsync().get();
    writer.FlushAsync().get();
    writer.DetachStream();
    stream.Seek(0);
    return stream;
}

bool ensure_ro_apartment()
{
    /*
     * Keep the Windows Runtime apartment alive for the complete worker-thread
     * lifetime.  Calling RoUninitialize while PdfDocument/OCR async objects are
     * still being finalized can terminate a console process during CRT teardown
     * before buffered audit output is flushed.  Windows releases the apartment
     * when the worker thread exits.
     */
    static thread_local HRESULT result = RoInitialize(RO_INIT_MULTITHREADED);
    return SUCCEEDED(result) || result == RPC_E_CHANGED_MODE;
}

} // namespace

extern "C" int windows_ocr_extract_utf8(
    const unsigned char* image_data,
    size_t image_length,
    char** output,
    size_t* output_length,
    char* status,
    size_t status_size)
{
    if (output == nullptr || output_length == nullptr || image_data == nullptr || image_length == 0) {
        set_status(status, status_size, "invalid image input");
        return -1;
    }
    *output = nullptr;
    *output_length = 0;

    if (!ensure_ro_apartment()) {
        set_status(status, status_size, "Windows Runtime initialization failed");
        return -1;
    }

    try {
        using namespace winrt::Windows::Graphics::Imaging;
        using namespace winrt::Windows::Media::Ocr;
        using namespace winrt::Windows::Storage::Streams;

        InMemoryRandomAccessStream stream = make_stream(image_data, image_length);

        BitmapDecoder decoder = BitmapDecoder::CreateAsync(stream).get();
        OcrEngine engine = OcrEngine::TryCreateFromUserProfileLanguages();
        if (engine == nullptr) {
            set_status(status, status_size,
                "Windows OCR language pack unavailable");
            return 0;
        }
        const uint32_t frame_count = decoder.FrameCount();
        const uint32_t maximum_frames = 100;
        if (frame_count == 0 || frame_count > maximum_frames) {
            set_status(status, status_size,
                frame_count == 0 ? "image contains no decodable frame" :
                "image frame count exceeds OCR safety limit");
            return 0;
        }
        const int32_t maximum_dimension = OcrEngine::MaxImageDimension();
        std::string combined;
        combined.reserve(4096);
        for (uint32_t index = 0; index < frame_count; ++index) {
            BitmapFrame frame = decoder.GetFrameAsync(index).get();
            SoftwareBitmap bitmap = frame.GetSoftwareBitmapAsync(
                BitmapPixelFormat::Bgra8,
                BitmapAlphaMode::Premultiplied).get();
            if (bitmap.PixelWidth() > maximum_dimension ||
                bitmap.PixelHeight() > maximum_dimension) {
                set_status(status, status_size, "image exceeds Windows OCR dimension limit");
                return 0;
            }
            OcrResult result = engine.RecognizeAsync(bitmap).get();
            std::string frame_text = winrt::to_string(result.Text());
            if (frame_count > 1) {
                combined += "\n--- OCR frame ";
                combined += std::to_string(index + 1);
                combined += " ---\n";
            }
            combined += frame_text;
            if (!frame_text.empty()) combined += '\n';
        }
        int copied = copy_result(combined, output, output_length);
        set_status(status, status_size,
            copied == 1 ? "Windows OCR completed" : "OCR output allocation failed");
        return copied;
    }
    catch (const winrt::hresult_error& error) {
        std::string message = winrt::to_string(error.message());
        set_status(status, status_size, message.c_str());
    }
    catch (...) {
        set_status(status, status_size, "unexpected Windows OCR failure");
    }

    return -1;
}

extern "C" int windows_pdf_ocr_extract_utf8(
    const unsigned char* pdf_data,
    size_t pdf_length,
    unsigned int max_pages,
    char** output,
    size_t* output_length,
    int* truncated,
    char* status,
    size_t status_size)
{
    if (output == nullptr || output_length == nullptr || pdf_data == nullptr || pdf_length == 0) {
        set_status(status, status_size, "invalid PDF input");
        return -1;
    }
    *output = nullptr;
    *output_length = 0;
    if (truncated != nullptr) *truncated = 0;
    if (max_pages == 0) max_pages = 100;

    if (!ensure_ro_apartment()) {
        set_status(status, status_size, "Windows Runtime initialization failed");
        return -1;
    }

    try {
        using namespace winrt::Windows::Data::Pdf;
        using namespace winrt::Windows::Graphics::Imaging;
        using namespace winrt::Windows::Media::Ocr;
        using namespace winrt::Windows::Storage::Streams;

        InMemoryRandomAccessStream input = make_stream(pdf_data, pdf_length);
        PdfDocument document = PdfDocument::LoadFromStreamAsync(input).get();
        OcrEngine engine = OcrEngine::TryCreateFromUserProfileLanguages();
        if (engine == nullptr) {
            set_status(status, status_size, "Windows OCR language pack unavailable");
            return 0;
        }

        const uint32_t page_count = document.PageCount();
        const uint32_t inspect_count = page_count < max_pages ? page_count : max_pages;
        bool incomplete = inspect_count < page_count;
        std::string combined;
        combined.reserve(4096);

        for (uint32_t index = 0; index < inspect_count; ++index) {
            PdfPage page = document.GetPage(index);
            InMemoryRandomAccessStream rendered;
            page.RenderToStreamAsync(rendered).get();
            rendered.Seek(0);
            BitmapDecoder decoder = BitmapDecoder::CreateAsync(rendered).get();
            SoftwareBitmap bitmap = decoder.GetSoftwareBitmapAsync(
                BitmapPixelFormat::Bgra8,
                BitmapAlphaMode::Premultiplied).get();
            const int32_t maximum_dimension = OcrEngine::MaxImageDimension();
            if (bitmap.PixelWidth() <= maximum_dimension &&
                bitmap.PixelHeight() <= maximum_dimension) {
                OcrResult result = engine.RecognizeAsync(bitmap).get();
                std::string page_text = winrt::to_string(result.Text());
                if (!page_text.empty()) {
                    combined += "\n--- PDF OCR page ";
                    combined += std::to_string(index + 1);
                    combined += " ---\n";
                    combined += page_text;
                    combined += '\n';
                }
            }
            else {
                incomplete = true;
            }
            page.Close();
        }

        if (truncated != nullptr && incomplete) *truncated = 1;

        int copied = copy_result(combined, output, output_length);
        set_status(status, status_size,
            copied == 1 ? "Windows PDF OCR completed" : "PDF OCR output allocation failed");
        return copied;
    }
    catch (const winrt::hresult_error& error) {
        std::string message = winrt::to_string(error.message());
        set_status(status, status_size, message.c_str());
    }
    catch (...) {
        set_status(status, status_size, "unexpected Windows PDF OCR failure");
    }

    return -1;
}
