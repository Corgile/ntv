//
// Created by corgi on 2025 四月 07.
//

#ifndef HELPERS_HH
#define HELPERS_HH
#include <wintoastlib.h>

using namespace WinToastLib;

class MyToastHandler : public IWinToastHandler {
public:
  inline void toastActivated() const {
    std::cout << "The user clicked in this toast" << std::endl;
    exit(0);
  }
  inline void toastActivated(int actionIndex) const {
    std::cout << "The user clicked on action #" << actionIndex << std::endl;
    exit(16 + actionIndex);
  }
  inline void toastActivated(const char* sth) const {
    std::cout << "The user clicked on action #" << sth << std::endl;
    exit(16);
  }

  inline void toastDismissed(WinToastDismissalReason state) const {
    switch (state) {
    case UserCanceled:
      std::cout << "The user dismissed this toast" << std::endl;
      exit(1);
      break;
    case TimedOut:
      std::cout << "The toast has timed out" << std::endl;
      exit(2);
      break;
    case ApplicationHidden:
      std::cout << "The application hid the toast using ToastNotifier.hide()"
                << std::endl;
      exit(3);
      break;
    default:
      std::cout << "Toast not activated" << std::endl;
      exit(4);
      break;
    }
  }
  inline void toastFailed() const {
    std::wcout << L"Error showing current toast" << std::endl;
    exit(5);
  }
};

static void ShowNotification(std::wstring&& appName, std::wstring&& firstLine,
                             std::wstring&& secondLine,
                             std::wstring&& imagePath,
                             std::wstring&& hero_imagePath) {
  std::wstring appUserModelID = L"NTV";
  WinToast::instance()->setAppName(appName);
  WinToast::instance()->setAppUserModelId(appUserModelID);

  WinToastTemplate templ = WinToastTemplate(WinToastTemplate::ImageAndText02);

  templ.setTextField(firstLine, WinToastTemplate::FirstLine);
  templ.setTextField(secondLine, WinToastTemplate::SecondLine);
  templ.setImagePath(imagePath, WinToastTemplate::CropHint::Circle);
  templ.setHeroImagePath(hero_imagePath);

  if (WinToast::instance()->initialize()) {
    WinToast::instance()->showToast(templ, new MyToastHandler());
    Sleep(5000);
  }
}
#endif // HELPERS_HH
