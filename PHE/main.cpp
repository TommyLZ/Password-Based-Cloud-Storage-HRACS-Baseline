#include "PublicParam.h"
#include "Registration.h"
#include "Encryption.h"
#include "Decryption.h"
#include "Upload.h"
#include "SingleQuery.h"
#include "BatchQuery.h"
#include "Update.h"

#include <iostream>
using namespace std;

int main()
{
    double totalTime1 = 0.0;
    double totalTime2 = 0.0;
    double totalTime3 = 0.0;
    double totalTime4 = 0.0;
    double totalTime5 = 0.0;
    double totalTime6 = 0.0;
    double totalTime7 = 0.0;

    string psw = "f4520tommy";
    ;
    string id = "wolverine";

    sysInitial();

    int numIterations = 20;
    for (int i = 0; i < numIterations; ++i)
    {
        auto start1 = chrono::high_resolution_clock::now();
        Registration(psw, id);
        auto end1 = chrono::high_resolution_clock::now();
        chrono::duration<double> duration1 = end1 - start1;
        totalTime1 += duration1.count();

        auto start2 = chrono::high_resolution_clock::now();
        Encryption(psw, id);
        auto end2 = chrono::high_resolution_clock::now();
        chrono::duration<double> duration2 = end2 - start2;
        totalTime2 += duration2.count();

        auto start3 = chrono::high_resolution_clock::now();
        Decryption(psw, id);
        auto end3 = chrono::high_resolution_clock::now();
        chrono::duration<double> duration3 = end3 - start3;
        totalTime3 += duration3.count();

        auto start4 = chrono::high_resolution_clock::now();
        Upload(psw, id);
        auto end4 = chrono::high_resolution_clock::now();
        chrono::duration<double> duration4 = end4 - start4;
        totalTime4 += duration4.count();

        auto start5 = chrono::high_resolution_clock::now();
        int index = 4;
        SingleQuery(psw, id, index);
        auto end5 = chrono::high_resolution_clock::now();
        chrono::duration<double> duration5 = end5 - start5;
        totalTime5 += duration5.count();

        auto start6 = chrono::high_resolution_clock::now();
        vector<int> indexList = {1, 2, 3, 4, 5};
        BatchQuery(psw, id, indexList);
        auto end6 = chrono::high_resolution_clock::now();
        chrono::duration<double> duration6 = end6 - start6;
        totalTime6 += duration6.count();

        auto start7 = chrono::high_resolution_clock::now();
        index = 4;
        Update(psw, id, index);
        auto end7 = chrono::high_resolution_clock::now();
        chrono::duration<double> duration7 = end7 - start7;
        totalTime7 += duration7.count();
    }

    double averageDuration1 = totalTime1 / numIterations;
    double averageDuration2 = totalTime2 / numIterations;
    double averageDuration3 = totalTime3 / numIterations;
    double averageDuration4 = totalTime4 / numIterations;
    double averageDuration5 = totalTime5 / numIterations;
    double averageDuration6 = totalTime6 / numIterations;
    double averageDuration7 = totalTime7 / numIterations;

    cout << "The average running time of Registration is: " << averageDuration1 << " seconds" << endl;
    cout << "The average running time of Key Give is: " << averageDuration2 << " seconds" << endl;
    cout << "The average running time of Key Take is: " << averageDuration3 << " seconds" << endl;
    cout << "The average running time of Upload is: " << averageDuration4 << " seconds" << endl;
    cout << "The average running time of SingleQuery is: " << averageDuration5 << " seconds" << endl;
    cout << "The average running time of BatchQuery is: " << averageDuration6 << " seconds" << endl;
    cout << "The average running time of Update is: " << averageDuration7 << " seconds" << endl;
    
    return 0;
}