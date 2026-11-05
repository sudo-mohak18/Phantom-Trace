import React, { useState } from 'react';
import {
  GraduationCap,
  HelpCircle,
  CheckCircle2,
  XCircle,
  RotateCcw,
  BookOpen,
  Award,
  Lightbulb,
  ArrowRight,
  ShieldCheck,
} from 'lucide-react';
import { QUIZ_QUESTIONS, EDUCATION_TOPICS, QuizQuestion, EducationTopic } from '../services/education';

export const CyberAwarenessMode: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'quiz' | 'modules'>('quiz');
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [selectedAnswer, setSelectedAnswer] = useState<'A' | 'B' | null>(null);
  const [score, setScore] = useState(0);
  const [quizCompleted, setQuizCompleted] = useState(false);
  const [activeTopic, setActiveTopic] = useState<EducationTopic>(EDUCATION_TOPICS[0]);

  const currentQ = QUIZ_QUESTIONS[currentQuestionIndex];

  const handleSelectOption = (choice: 'A' | 'B') => {
    if (selectedAnswer !== null) return; // Prevent changing after answer
    setSelectedAnswer(choice);

    if (choice === currentQ.correctChoice) {
      setScore(prev => prev + 1);
    }
  };

  const handleNextQuestion = () => {
    if (currentQuestionIndex < QUIZ_QUESTIONS.length - 1) {
      setCurrentQuestionIndex(prev => prev + 1);
      setSelectedAnswer(null);
    } else {
      setQuizCompleted(true);
    }
  };

  const handleResetQuiz = () => {
    setCurrentQuestionIndex(0);
    setSelectedAnswer(null);
    setScore(0);
    setQuizCompleted(false);
  };

  return (
    <div className="bg-[#0b0f19]/90 border border-slate-800/80 rounded-2xl p-6 shadow-xl relative">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
        <div>
          <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
            <GraduationCap className="w-5 h-5 text-cyan-400" />
            Cyber Awareness & Forensic Training Center
          </h3>
          <p className="text-xs text-slate-400">
            Learn to spot sophisticated cyber deception, homoglyphs, and phishing pretexts through interactive simulations.
          </p>
        </div>

        {/* Tab switch */}
        <div className="flex items-center bg-[#07090e] p-1 rounded-xl border border-slate-800 text-xs self-start sm:self-auto">
          <button
            onClick={() => setActiveTab('quiz')}
            className={`px-3 py-1.5 font-semibold rounded-lg flex items-center gap-1.5 transition-all ${
              activeTab === 'quiz'
                ? 'bg-purple-950 text-cyan-300 border border-purple-800/60'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <HelpCircle className="w-3.5 h-3.5" />
            <span>Spot the Phish Quiz</span>
          </button>
          <button
            onClick={() => setActiveTab('modules')}
            className={`px-3 py-1.5 font-semibold rounded-lg flex items-center gap-1.5 transition-all ${
              activeTab === 'modules'
                ? 'bg-purple-950 text-cyan-300 border border-purple-800/60'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <BookOpen className="w-3.5 h-3.5" />
            <span>Learning Modules</span>
          </button>
        </div>
      </div>

      {activeTab === 'quiz' ? (
        <div>
          {!quizCompleted ? (
            <div className="bg-[#0e1424] border border-slate-800 rounded-xl p-6">
              {/* Question Header & Progress Bar */}
              <div className="flex items-center justify-between mb-4">
                <span className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">
                  Challenge {currentQuestionIndex + 1} of {QUIZ_QUESTIONS.length}
                </span>
                <span className="text-xs font-mono text-slate-400">
                  Current Score: <strong className="text-white">{score}</strong> / {QUIZ_QUESTIONS.length}
                </span>
              </div>

              {/* Progress Track */}
              <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden mb-6">
                <div
                  className="bg-gradient-to-r from-purple-500 to-cyan-400 h-full transition-all duration-300"
                  style={{ width: `${((currentQuestionIndex) / QUIZ_QUESTIONS.length) * 100}%` }}
                />
              </div>

              {/* Scenario Context */}
              <div className="mb-6">
                <span className="text-[10px] font-mono uppercase tracking-wider text-purple-400 font-bold block mb-1">
                  Scenario Context
                </span>
                <h4 className="text-base font-bold text-white mb-1.5">
                  {currentQ.scenario}
                </h4>
                <p className="text-xs text-slate-400">
                  Hint: {currentQ.context}
                </p>
              </div>

              {/* Options A & B Comparison Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                {/* Option A */}
                <div
                  onClick={() => handleSelectOption('A')}
                  className={`p-4 rounded-xl border text-left cursor-pointer transition-all ${
                    selectedAnswer === null
                      ? 'bg-[#07090e] border-slate-800 hover:border-purple-600 hover:bg-slate-900/60'
                      : selectedAnswer === 'A'
                      ? currentQ.correctChoice === 'A'
                        ? 'bg-emerald-950/60 border-emerald-600'
                        : 'bg-red-950/60 border-red-600'
                      : currentQ.correctChoice === 'A'
                      ? 'bg-emerald-950/40 border-emerald-700'
                      : 'bg-[#07090e] border-slate-800 opacity-60'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="w-6 h-6 rounded-lg bg-slate-800 text-xs font-bold font-mono flex items-center justify-center text-slate-200">
                      A
                    </span>
                    {selectedAnswer !== null && (
                      currentQ.correctChoice === 'A' ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      ) : selectedAnswer === 'A' ? (
                        <XCircle className="w-4 h-4 text-red-400" />
                      ) : null
                    )}
                  </div>
                  <p className="font-mono text-xs text-slate-200 break-all bg-slate-950 p-2.5 rounded border border-slate-800 mb-2 font-medium">
                    {currentQ.optionA.label}
                  </p>
                  <p className="text-xs text-slate-400">
                    {currentQ.optionA.detail}
                  </p>
                </div>

                {/* Option B */}
                <div
                  onClick={() => handleSelectOption('B')}
                  className={`p-4 rounded-xl border text-left cursor-pointer transition-all ${
                    selectedAnswer === null
                      ? 'bg-[#07090e] border-slate-800 hover:border-purple-600 hover:bg-slate-900/60'
                      : selectedAnswer === 'B'
                      ? currentQ.correctChoice === 'B'
                        ? 'bg-emerald-950/60 border-emerald-600'
                        : 'bg-red-950/60 border-red-600'
                      : currentQ.correctChoice === 'B'
                      ? 'bg-emerald-950/40 border-emerald-700'
                      : 'bg-[#07090e] border-slate-800 opacity-60'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="w-6 h-6 rounded-lg bg-slate-800 text-xs font-bold font-mono flex items-center justify-center text-slate-200">
                      B
                    </span>
                    {selectedAnswer !== null && (
                      currentQ.correctChoice === 'B' ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      ) : selectedAnswer === 'B' ? (
                        <XCircle className="w-4 h-4 text-red-400" />
                      ) : null
                    )}
                  </div>
                  <p className="font-mono text-xs text-slate-200 break-all bg-slate-950 p-2.5 rounded border border-slate-800 mb-2 font-medium">
                    {currentQ.optionB.label}
                  </p>
                  <p className="text-xs text-slate-400">
                    {currentQ.optionB.detail}
                  </p>
                </div>
              </div>

              {/* Forensic Feedback Drawer after choice */}
              {selectedAnswer !== null && (
                <div className="p-4 bg-[#07090e] border border-slate-800 rounded-xl space-y-3 mb-6">
                  <div className="flex items-center justify-between">
                    <span className={`text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 ${
                      selectedAnswer === currentQ.correctChoice ? 'text-emerald-400' : 'text-red-400'
                    }`}>
                      {selectedAnswer === currentQ.correctChoice ? (
                        <>
                          <CheckCircle2 className="w-4 h-4" />
                          <span>Correct Forensic Decision!</span>
                        </>
                      ) : (
                        <>
                          <XCircle className="w-4 h-4" />
                          <span>Dangerous Choice (Phishing Trapped)</span>
                        </>
                      )}
                    </span>
                    <span className="text-[11px] font-mono text-purple-400">
                      Technique: {currentQ.threatType}
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed">
                    {currentQ.explanation}
                  </p>

                  <div className="pt-2 border-t border-slate-800/80">
                    <span className="text-[10px] font-mono uppercase text-slate-400 font-bold block mb-1">
                      Key Investigative Clues:
                    </span>
                    <ul className="text-xs text-cyan-300 list-disc list-inside space-y-0.5">
                      {currentQ.keyClues.map((clue, idx) => (
                        <li key={idx}>{clue}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}

              {/* Action Button */}
              {selectedAnswer !== null && (
                <div className="flex justify-end">
                  <button
                    onClick={handleNextQuestion}
                    className="px-5 py-2 text-xs font-bold rounded-xl bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 text-white flex items-center gap-1.5 transition-all shadow-md shadow-purple-950/50"
                  >
                    <span>{currentQuestionIndex < QUIZ_QUESTIONS.length - 1 ? 'Next Challenge' : 'Complete Quiz'}</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
            </div>
          ) : (
            /* Quiz Results Summary Screen */
            <div className="bg-[#0e1424] border border-slate-800 rounded-xl p-8 text-center max-w-lg mx-auto">
              <Award className="w-12 h-12 text-cyan-400 mx-auto mb-3" />
              <h4 className="text-lg font-bold text-white">Quiz Completed!</h4>
              <p className="text-xs text-slate-400 mt-1 mb-4">
                You correctly identified <strong className="text-white font-mono text-sm">{score}</strong> out of <strong className="text-white font-mono text-sm">{QUIZ_QUESTIONS.length}</strong> phishing scenarios.
              </p>

              <div className="p-4 bg-[#07090e] rounded-xl border border-slate-800 mb-6 text-xs text-slate-300">
                {score === QUIZ_QUESTIONS.length
                  ? '🏆 Perfect Forensic Score! You possess sharp intuition for homoglyphs, subdomain trickery, and email forgery.'
                  : score >= 4
                  ? '🛡️ Strong Security Awareness! You successfully recognized the majority of subtle cyber attacks.'
                  : '⚠️ Practice Recommended: Cybercriminals rely on hasty clicks. Review the Learning Modules tab to master typosquat and header inspection.'}
              </div>

              <button
                onClick={handleResetQuiz}
                className="px-4 py-2 text-xs font-bold rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 inline-flex items-center gap-1.5 transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Retake Quiz</span>
              </button>
            </div>
          )}
        </div>
      ) : (
        /* Learning Modules Tab */
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Module Selection Sidebar */}
          <div className="space-y-2">
            {EDUCATION_TOPICS.map(topic => (
              <button
                key={topic.id}
                onClick={() => setActiveTopic(topic)}
                className={`w-full text-left p-3.5 rounded-xl border transition-all ${
                  activeTopic.id === topic.id
                    ? 'bg-purple-950/40 border-purple-600 text-white'
                    : 'bg-[#0e1424] border-slate-800 text-slate-300 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between text-[10px] font-mono uppercase text-cyan-400 mb-1">
                  <span>{topic.category}</span>
                  <span className="text-slate-500">{topic.readingTime}</span>
                </div>
                <h4 className="text-xs font-bold text-white mb-1">
                  {topic.title}
                </h4>
                <p className="text-[11px] text-slate-400 line-clamp-2">
                  {topic.tagline}
                </p>
              </button>
            ))}
          </div>

          {/* Module Reader Area */}
          <div className="md:col-span-2 bg-[#0e1424] border border-slate-800 rounded-xl p-6">
            <div className="pb-4 border-b border-slate-800 mb-5">
              <span className="text-[10px] font-mono text-purple-400 uppercase font-bold">
                {activeTopic.category} • {activeTopic.readingTime} Read
              </span>
              <h3 className="text-lg font-bold text-white mt-1">
                {activeTopic.title}
              </h3>
              <p className="text-xs text-slate-300 mt-2 leading-relaxed">
                {activeTopic.summary}
              </p>
            </div>

            <div className="space-y-6">
              {activeTopic.sections.map((sec, idx) => (
                <div key={idx} className="space-y-2">
                  <h4 className="text-sm font-bold text-white flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                    <span>{sec.heading}</span>
                  </h4>
                  <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-line pl-3.5 border-l border-slate-800">
                    {sec.content}
                  </p>
                  {sec.proTip && (
                    <div className="ml-3.5 mt-2 bg-purple-950/30 border border-purple-800/50 rounded-lg p-2.5 flex items-start gap-2">
                      <Lightbulb className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
                      <p className="text-[11px] text-purple-200">
                        <strong className="text-amber-300">Pro-Tip: </strong>
                        {sec.proTip}
                      </p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
